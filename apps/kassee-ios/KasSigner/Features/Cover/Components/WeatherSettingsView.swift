import SwiftUI

struct WeatherSettingsView: View {
    @EnvironmentObject private var appLockService: AppLockService
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var model: WeatherCoverModel
    @AppStorage(WeatherCoverKey.enabled) private var decoyEnabled = false
    @AppStorage(WeatherCoverKey.cityName) private var cityName = "New York"
    @AppStorage(WeatherCoverKey.latitude) private var latitude = 40.7128
    @AppStorage(WeatherCoverKey.longitude) private var longitude = -74.0060
    @AppStorage(WeatherCoverKey.temperatureUnit) private var temperatureUnit = "fahrenheit"
    @State private var query = ""
    @State private var showingCitySearch = false
    @State private var showingResetConfirmation = false

    let close: () -> Void

    var body: some View {
        NavigationStack {
            Form {
                Section("Location") {
                    Button {
                        showingCitySearch = true
                    } label: {
                        LabeledContent("City", value: cityName)
                    }
                    .foregroundStyle(.primary)

                    Picker("Temperature", selection: $temperatureUnit) {
                        Text("Fahrenheit").tag("fahrenheit")
                        Text("Celsius").tag("celsius")
                    }
                    .pickerStyle(.segmented)
                }

                Section {
                    Button("Refresh Weather") {
                        Task {
                            await model.refresh(
                                latitude: latitude,
                                longitude: longitude,
                                fahrenheit: temperatureUnit == "fahrenheit"
                            )
                        }
                    }
                }

                Section {
                    Button("Reset Weather App", role: .destructive) {
                        showingResetConfirmation = true
                    }
                } footer: {
                    Text("Clears saved weather information. The app itself can be removed from the Home Screen.")
                }
            }
            .navigationTitle("Weather Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { close() }
                }
            }
            .sheet(isPresented: $showingCitySearch) {
                CitySearchView(model: model) { location in
                    model.clearCache()
                    cityName = location.name
                    latitude = location.latitude
                    longitude = location.longitude
                    showingCitySearch = false
                    Task {
                        await model.refresh(
                            latitude: location.latitude,
                            longitude: location.longitude,
                            fahrenheit: temperatureUnit == "fahrenheit"
                        )
                    }
                }
            }
            .confirmationDialog(
                "Reset weather information?",
                isPresented: $showingResetConfirmation,
                titleVisibility: .visible
            ) {
                Button("Reset Weather App", role: .destructive) {
                    Task {
                        guard await appLockService.authorizePrivacyCoverChange() else { return }
                        model.clearCache()
                        UserDefaults.standard.removeObject(forKey: WeatherCoverKey.cityName)
                        UserDefaults.standard.removeObject(forKey: WeatherCoverKey.latitude)
                        UserDefaults.standard.removeObject(forKey: WeatherCoverKey.longitude)
                        decoyEnabled = false
                        dismiss()
                    }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("This clears saved cities and weather data after authentication.")
            }
        }
    }
}
