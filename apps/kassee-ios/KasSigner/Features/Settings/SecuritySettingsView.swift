import SwiftUI

struct SecuritySettingsView: View {
    let onHome: (() -> Void)?

    init(onHome: (() -> Void)? = nil) {
        self.onHome = onHome
    }
    @EnvironmentObject private var appLockService: AppLockService
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    @State private var appLockToggle = false

    var body: some View {
        Form {
            Section {
                Toggle(appLockService.biometricName, isOn: $appLockToggle)
                    .disabled(appLockService.isAuthenticating)
                    .onChange(of: appLockToggle) { oldValue, newValue in
                        guard oldValue != newValue,
                              newValue != appLockService.isEnabled else { return }
                        Task {
                            let succeeded = newValue
                                ? await appLockService.enableAppLock()
                                : await appLockService.disableAppLock()
                            if !succeeded {
                                appLockToggle = appLockService.isEnabled
                            }
                        }
                    }

                if appLockService.isEnabled {
                    Menu {
                        ForEach(AppLockService.LockDelay.allCases) { delay in
                            Button {
                                appLockService.lockDelay = delay
                            } label: {
                                if appLockService.lockDelay == delay {
                                    Label(delay.title, systemImage: "checkmark")
                                } else {
                                    Text(delay.title)
                                }
                            }
                        }
                    } label: {
                        if dynamicTypeSize.isAccessibilitySize {
                            VStack(alignment: .leading, spacing: 8) {
                                Text("Authentication")
                                    .foregroundStyle(.primary)
                                HStack {
                                    Spacer()
                                    collapsedLockDelayLabel
                                }
                            }
                        } else {
                            HStack {
                                Text("Authentication")
                                    .foregroundStyle(.primary)
                                Spacer()
                                collapsedLockDelayLabel
                            }
                        }
                    }
                }
            } header: {
                Text("Biometrics")
            } footer: {
                Text("Use \(appLockService.biometricName) or your device passcode to unlock KasSigner.")
            }

            Section("Privacy") {
                Toggle("Hide App Switcher Preview", isOn: $appLockService.hideAppSwitcherPreview)
                NavigationLink("Decoy Launch") {
                    DecoyLaunchSettingsView(onHome: onHome)
                }
            }
        }
        .navigationTitle("Security")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear {
            appLockToggle = appLockService.isEnabled
        }
        .alert("Authentication Unavailable", isPresented: authenticationAlertPresented) {
            Button("OK", role: .cancel) {
                appLockService.authenticationError = nil
            }
        } message: {
            Text(appLockService.authenticationError ?? "Authentication could not be completed.")
        }
    }

    private var authenticationAlertPresented: Binding<Bool> {
        Binding(
            get: { appLockService.authenticationError != nil },
            set: { if !$0 { appLockService.authenticationError = nil } }
        )
    }

    private var collapsedLockDelayTitle: String {
        switch appLockService.lockDelay {
        case .immediately: "Immediately"
        case .oneMinute: "1 Minute"
        case .fiveMinutes: "5 Minutes"
        }
    }

    private var collapsedLockDelayLabel: some View {
        HStack(spacing: 6) {
            Text(collapsedLockDelayTitle)
            Image(systemName: "chevron.up.chevron.down")
                .font(.caption.weight(.semibold))
        }
    }
}
