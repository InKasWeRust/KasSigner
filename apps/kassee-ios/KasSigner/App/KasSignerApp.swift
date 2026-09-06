import SwiftUI

@main
struct KasSignerApp: App {
    @StateObject private var preferences = AppPreferences()
    @StateObject private var appLockService = AppLockService()

    var body: some Scene {
        WindowGroup {
            AppSecurityContainer {
                RootView()
            }
                .preferredColorScheme(preferredColorScheme)
                .environmentObject(preferences)
                .environmentObject(appLockService)
        }
    }

    private var preferredColorScheme: ColorScheme? {
        switch preferences.appearanceTheme {
        case .system: nil
        case .light: .light
        case .dark: .dark
        }
    }
}

private struct AppSecurityContainer<Content: View>: View {
    @EnvironmentObject private var appLockService: AppLockService
    @Environment(\.scenePhase) private var scenePhase
    @AppStorage("kassigner.security.decoyLaunchScreenEnabled")
    private var decoyLaunchScreenEnabled = false
    @State private var privacyCoverUnlocked = false

    let content: Content

    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    var body: some View {
        ZStack {
            if appLockService.isEnabled &&
                decoyLaunchScreenEnabled &&
                !privacyCoverUnlocked &&
                !appLockService.isPrivacyCoverSuspendedForSession {
                WeatherCoverView {
                    if await appLockService.unlockFromPrivacyCover() {
                        privacyCoverUnlocked = true
                    }
                }
                .zIndex(2)
            } else {
                content

                if shouldCoverContent {
                    Color(uiColor: .systemBackground)
                        .ignoresSafeArea()
                        .overlay {
                            if scenePhase == .active, appLockService.isLocked {
                                lockedView
                            }
                        }
                        .transition(.opacity)
                        .zIndex(1)
                }
            }
        }
        .onChange(of: scenePhase) { _, newPhase in
            switch newPhase {
            case .background:
                privacyCoverUnlocked = false
                appLockService.sceneDidEnterBackground()
            case .active:
                appLockService.sceneDidBecomeActive()
                if appLockService.isLocked && !decoyLaunchScreenEnabled {
                    Task { await appLockService.unlock() }
                }
            default:
                break
            }
        }
        .task {
            if appLockService.isLocked && !decoyLaunchScreenEnabled {
                await appLockService.unlock()
            }
        }
        .onChange(of: decoyLaunchScreenEnabled) { _, _ in
            // Enabling the cover from Security settings must not hide those
            // settings before the user finishes choosing the unlock gesture.
            // The cover takes effect after the app backgrounds or relaunches.
            privacyCoverUnlocked = true
        }
    }

    private var shouldCoverContent: Bool {
        appLockService.isLocked ||
            (appLockService.hideAppSwitcherPreview && scenePhase != .active)
    }

    private var lockedView: some View {
        VStack(spacing: 18) {
            Image(systemName: "lock.shield.fill")
                .font(.system(size: 48))
                .foregroundStyle(.tint)

            Text("KasSigner Locked")
                .font(.title2.weight(.semibold))

            Button {
                Task { await appLockService.unlock() }
            } label: {
                Text("Unlock KasSigner")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(appLockService.isAuthenticating)
            .frame(maxWidth: 280)
        }
        .padding()
    }
}
