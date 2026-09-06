import SwiftUI

struct DecoyLaunchSettingsView: View {
    let onHome: (() -> Void)?
    @Environment(\.dismiss) private var dismiss

    init(onHome: (() -> Void)? = nil) {
        self.onHome = onHome
    }
    @EnvironmentObject private var appLockService: AppLockService
    @AppStorage(WeatherCoverKey.enabled) private var enabled = false
    @AppStorage(WeatherCoverKey.unlockTarget) private var unlockTarget = WeatherUnlockTarget.conditionIcon.rawValue
    @AppStorage(WeatherCoverKey.unlockTapCount) private var unlockTapCount = 3
    @State private var toggleValue = false

    var body: some View {
        Form {
            Section {
                Toggle("Weather Cover", isOn: $toggleValue)
                    .disabled(appLockService.isAuthenticating || !appLockService.isEnabled)
                    .onChange(of: toggleValue) { oldValue, newValue in
                        guard oldValue != newValue, newValue != enabled else { return }
                        Task {
                            if await appLockService.authorizePrivacyCoverChange() {
                                appLockService.suspendPrivacyCoverForCurrentSession()
                                enabled = newValue
                            } else {
                                toggleValue = enabled
                            }
                        }
                    }
            } footer: {
                if appLockService.isEnabled {
                    Text("When enabled, KasSigner opens to a functional weather screen.")
                } else {
                    Text("Turn on Face ID in Security before enabling Weather Cover.")
                }
            }

            if enabled {
                Section {
                    Picker("Tap", selection: $unlockTarget) {
                        ForEach(WeatherUnlockTarget.allCases) { target in
                            Text(target.title).tag(target.rawValue)
                        }
                    }
                    Picker("Number of Taps", selection: $unlockTapCount) {
                        ForEach(2...7, id: \.self) { count in
                            Text("\(count)").tag(count)
                        }
                    }
                } header: {
                    Text("Unlock Gesture")
                } footer: {
                    Text("Tap the selected weather item the chosen number of times, then authenticate to open protected content.")
                }
            }
        }
        .navigationTitle("Decoy Launch")
        .navigationBarTitleDisplayMode(.inline)
        .navigationBarBackButtonHidden(onHome != nil)
        .toolbar {
            if let onHome {
                ToolbarItemGroup(placement: .topBarLeading) {
                    Button("Back") { dismiss() }
                    Button("Home") { onHome() }
                }
            }
        }
        .onAppear {
            if !appLockService.isEnabled {
                enabled = false
            }
            toggleValue = enabled
        }
        .onChange(of: appLockService.isEnabled) { _, appLockEnabled in
            if !appLockEnabled {
                enabled = false
                toggleValue = false
            }
        }
    }
}
