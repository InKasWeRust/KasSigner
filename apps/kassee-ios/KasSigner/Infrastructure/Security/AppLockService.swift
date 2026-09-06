import LocalAuthentication
import SwiftUI

@MainActor
final class AppLockService: ObservableObject {
    enum LockDelay: String, CaseIterable, Identifiable {
        case immediately
        case oneMinute
        case fiveMinutes

        var id: String { rawValue }

        var title: String {
            switch self {
            case .immediately: "Immediately"
            case .oneMinute: "After 1 Minute"
            case .fiveMinutes: "After 5 Minutes"
            }
        }

        var interval: TimeInterval {
            switch self {
            case .immediately: 0
            case .oneMinute: 60
            case .fiveMinutes: 300
            }
        }
    }

    struct AuthenticationSession {
        let canEvaluate: () -> (Bool, String?)
        let evaluate: (String) async throws -> Bool
    }

    private enum Key {
        static let isEnabled = "kassigner.security.appLockEnabled"
        static let lockDelay = "kassigner.security.lockDelay"
        static let hideAppSwitcherPreview = "kassigner.security.hideAppSwitcherPreview"
        static let privacyCoverEnabled = "kassigner.security.decoyLaunchScreenEnabled"
    }

    @Published private(set) var isLocked: Bool
    @Published private(set) var isAuthenticating = false
    @Published private(set) var isPrivacyCoverSuspendedForSession = false
    @Published var authenticationError: String?

    @Published var isEnabled: Bool {
        didSet { defaults.set(isEnabled, forKey: Key.isEnabled) }
    }

    @Published var lockDelay: LockDelay {
        didSet { defaults.set(lockDelay.rawValue, forKey: Key.lockDelay) }
    }

    @Published var hideAppSwitcherPreview: Bool {
        didSet { defaults.set(hideAppSwitcherPreview, forKey: Key.hideAppSwitcherPreview) }
    }

    private let defaults: UserDefaults
    private let authenticationSessionFactory: () -> AuthenticationSession
    private let now: () -> Date
    private var backgroundedAt: Date?

    init(
        defaults: UserDefaults = .standard,
        authenticationSessionFactory: (() -> AuthenticationSession)? = nil,
        now: @escaping () -> Date = { Date() }
    ) {
        self.defaults = defaults
        self.authenticationSessionFactory = authenticationSessionFactory ?? AppLockService.liveAuthenticationSession
        self.now = now
        let enabled = defaults.bool(forKey: Key.isEnabled)
        isEnabled = enabled
        lockDelay = LockDelay(rawValue: defaults.string(forKey: Key.lockDelay) ?? "") ?? .immediately
        hideAppSwitcherPreview = defaults.object(forKey: Key.hideAppSwitcherPreview) as? Bool ?? true
        isLocked = enabled
        if !enabled {
            defaults.set(false, forKey: Key.privacyCoverEnabled)
        }
    }

    var biometricName: String {
        let context = LAContext()
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        return switch context.biometryType {
        case .faceID: "Face ID"
        case .touchID: "Touch ID"
        default: "Biometrics"
        }
    }

    func enableAppLock() async -> Bool {
        let succeeded = await authenticate(reason: "Use Face ID to enable App Lock.")
        if succeeded {
            isEnabled = true
            isLocked = false
        }
        return succeeded
    }

    func disableAppLock() async -> Bool {
        let succeeded = await authenticate(reason: "Authenticate to turn off App Lock.")
        if succeeded {
            isEnabled = false
            isLocked = false
            defaults.set(false, forKey: Key.privacyCoverEnabled)
        }
        return succeeded
    }

    func unlock() async {
        guard isEnabled, isLocked else { return }
        if await authenticate(reason: "Unlock KasSigner") {
            isLocked = false
        }
    }

    func unlockFromPrivacyCover() async -> Bool {
        guard isEnabled else { return false }
        guard isLocked else { return true }
        let succeeded = await authenticate(reason: "Open protected content")
        if succeeded {
            isLocked = false
        }
        return succeeded
    }

    func authorizePrivacyCoverChange() async -> Bool {
        await authenticate(reason: "Change Privacy Cover settings")
    }

    func suspendPrivacyCoverForCurrentSession() {
        isPrivacyCoverSuspendedForSession = true
    }

    func sceneDidEnterBackground() {
        isPrivacyCoverSuspendedForSession = false
        backgroundedAt = now()
        if isEnabled, lockDelay == .immediately {
            isLocked = true
        }
    }

    func sceneDidBecomeActive() {
        guard isEnabled, let backgroundedAt else {
            backgroundedAt = nil
            return
        }
        if now().timeIntervalSince(backgroundedAt) >= lockDelay.interval {
            isLocked = true
        }
        self.backgroundedAt = nil
    }

    private func authenticate(reason: String) async -> Bool {
        guard !isAuthenticating else { return false }
        isAuthenticating = true
        authenticationError = nil
        defer { isAuthenticating = false }

        let session = authenticationSessionFactory()
        let availability = session.canEvaluate()
        guard availability.0 else {
            authenticationError = availability.1 ?? "Face ID or a device passcode is not available."
            return false
        }
        do {
            return try await session.evaluate(reason)
        } catch {
            recordAuthenticationFailure(error)
            return false
        }
    }

    static func liveAuthenticationSession() -> AuthenticationSession {
        let context = LAContext()
        context.localizedCancelTitle = "Cancel"
        return AuthenticationSession(
            canEvaluate: {
                var error: NSError?
                let available = context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)
                return (available, error?.localizedDescription)
            },
            evaluate: { reason in
                try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
            }
        )
    }

    private func recordAuthenticationFailure(_ error: Error) {
        let code = LAError.Code(rawValue: (error as NSError).code)
        let cancelled = code == .userCancel || code == .appCancel || code == .systemCancel
        if !cancelled { authenticationError = error.localizedDescription }
    }
}
