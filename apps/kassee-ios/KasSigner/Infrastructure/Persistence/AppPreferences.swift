import Foundation

enum AppearanceTheme: String, CaseIterable, Identifiable {
    case system
    case light
    case dark

    var id: String { rawValue }
}

/// Native-shell appearance only. Wallet preferences live in the embedded KasSee application.
@MainActor
final class AppPreferences: ObservableObject {
    @Published var appearanceTheme: AppearanceTheme { didSet { save() } }

    private static let appearanceKey = "kassigner.appearanceTheme.v1"

    init() {
        appearanceTheme = AppearanceTheme(
            rawValue: UserDefaults.standard.string(forKey: Self.appearanceKey) ?? ""
        ) ?? .system
    }

    private func save() {
        UserDefaults.standard.set(appearanceTheme.rawValue, forKey: Self.appearanceKey)
    }
}
