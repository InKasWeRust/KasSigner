import SwiftUI

struct WeatherCoverView: View {
    @StateObject private var model = WeatherCoverModel()
    @AppStorage(WeatherCoverKey.cityName) private var cityName = "New York"
    @AppStorage(WeatherCoverKey.latitude) private var latitude = 40.7128
    @AppStorage(WeatherCoverKey.longitude) private var longitude = -74.0060
    @AppStorage(WeatherCoverKey.temperatureUnit) private var temperatureUnit = "fahrenheit"
    @AppStorage(WeatherCoverKey.unlockTarget) private var unlockTarget = WeatherUnlockTarget.conditionIcon.rawValue
    @AppStorage(WeatherCoverKey.unlockTapCount) private var unlockTapCount = 3
    @State private var showingSettings = false
    @State private var tapSequenceCount = 0
    @State private var tapSequenceID = UUID()
    @State private var tapEvaluationTask: Task<Void, Never>?
    @State private var isUnlockRequestInFlight = false

    let requestUnlock: () async -> Void

    var body: some View {
        NavigationStack {
            ZStack {
                LinearGradient(
                    colors: [Color.blue.opacity(0.72), Color.cyan.opacity(0.32), Color(uiColor: .systemBackground)],
                    startPoint: .top,
                    endPoint: .bottom
                )
                .ignoresSafeArea()

                ScrollView {
                    VStack(spacing: 24) {
                        locationHeader
                        currentConditions
                        forecastCard
                        updateStatus
                        if let attributionURL = URL(string: "https://open-meteo.com/") {
                            Link("Weather data by Open-Meteo", destination: attributionURL)
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .padding(.horizontal, 20)
                    .padding(.bottom, 30)
                }
                .refreshable { await refresh() }
            }
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button { showingSettings = true } label: {
                        Image(systemName: "gearshape.fill")
                    }
                    .accessibilityLabel("Weather settings")
                }
            }
            .sheet(isPresented: $showingSettings) {
                WeatherSettingsView(model: model) {
                    showingSettings = false
                }
            }
            .task { await refresh() }
            .onChange(of: temperatureUnit) { _, _ in
                model.clearCache()
                Task { await refresh() }
            }
        }
        .tint(.primary)
        .onDisappear { resetTapSequence() }
    }

    private var locationHeader: some View {
        VStack(spacing: 5) {
            Text(cityName)
                .font(.title2.weight(.semibold))
                .contentShape(Rectangle())
                .onTapGesture {
                    recordTap(on: .location)
                }
            Text(Date.now.formatted(date: .complete, time: .omitted))
                .font(.subheadline)
                .foregroundStyle(.secondary)
        }
        .padding(.top, 12)
    }

    private var currentConditions: some View {
        VStack(spacing: 12) {
            Image(systemName: weatherSymbol(model.snapshot?.weatherCode))
                .symbolRenderingMode(.multicolor)
                .font(.system(size: 92, weight: .light))
                .contentShape(Rectangle())
                .onTapGesture {
                    recordTap(on: .conditionIcon)
                }

            Text(temperature(model.snapshot?.temperature))
                .font(.system(size: 72, weight: .thin, design: .rounded))
                .contentShape(Rectangle())
                .onTapGesture {
                    recordTap(on: .temperature)
                }

            Text(conditionName(model.snapshot?.weatherCode))
                .font(.title3.weight(.medium))

            if let snapshot = model.snapshot {
                Text("Feels like \(temperature(snapshot.apparentTemperature))  •  Wind \(Int(snapshot.windSpeed.rounded())) \(isFahrenheit ? "mph" : "km/h")")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var forecastCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("6-DAY FORECAST")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)

            if let days = model.snapshot?.daily, !days.isEmpty {
                ForEach(Array(days.enumerated()), id: \.element.id) { index, day in
                    if index > 0 { Divider() }
                    HStack {
                        Text(index == 0 ? "Today" : day.date.formatted(.dateTime.weekday(.abbreviated)))
                            .frame(width: 54, alignment: .leading)
                            .lineLimit(1)
                            .minimumScaleFactor(0.8)
                        Image(systemName: weatherSymbol(day.weatherCode))
                            .symbolRenderingMode(.multicolor)
                            .frame(maxWidth: .infinity)
                        Text("\(Int(day.low.rounded()))°")
                            .foregroundStyle(.secondary)
                        Text("\(Int(day.high.rounded()))°")
                            .frame(width: 38, alignment: .trailing)
                    }
                    .font(.body.weight(.medium))
                }
            } else if model.isRefreshing {
                ProgressView().frame(maxWidth: .infinity)
            } else {
                Text("Forecast unavailable")
                    .foregroundStyle(.secondary)
            }
        }
        .padding(18)
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 22, style: .continuous))
    }

    @ViewBuilder
    private var updateStatus: some View {
        if model.isRefreshing {
            Label("Updating weather…", systemImage: "arrow.triangle.2.circlepath")
                .font(.footnote)
                .foregroundStyle(.secondary)
        } else if let message = model.message {
            Text(message).font(.footnote).foregroundStyle(.secondary)
        } else if let updatedAt = model.snapshot?.updatedAt {
            Text("Updated \(updatedAt.formatted(date: .omitted, time: .shortened))")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }

    private var target: WeatherUnlockTarget {
        WeatherUnlockTarget(rawValue: unlockTarget) ?? .conditionIcon
    }

    private var isFahrenheit: Bool { temperatureUnit == "fahrenheit" }

    private func refresh() async {
        await model.refresh(latitude: latitude, longitude: longitude, fahrenheit: isFahrenheit)
    }

    private var requiredTapCount: Int {
        min(max(unlockTapCount, 2), 7)
    }

    private func recordTap(on tappedTarget: WeatherUnlockTarget) {
        guard target == tappedTarget, !isUnlockRequestInFlight else { return }
        tapSequenceCount += 1
        let sequenceID = UUID()
        tapSequenceID = sequenceID
        tapEvaluationTask?.cancel()
        tapEvaluationTask = Task { @MainActor in await evaluateTapSequence(sequenceID) }
    }

    private func evaluateTapSequence(_ sequenceID: UUID) async {
        guard await waitForTapWindow(), tapSequenceID == sequenceID else { return }
        let completedCount = tapSequenceCount
        resetTapSequence()
        guard completedCount == requiredTapCount else { return }
        isUnlockRequestInFlight = true
        await requestUnlock()
        isUnlockRequestInFlight = false
    }

    private func waitForTapWindow() async -> Bool {
        do {
            try await Task.sleep(for: .milliseconds(500))
            return true
        } catch {
            return false
        }
    }

    private func resetTapSequence() {
        tapEvaluationTask?.cancel()
        tapEvaluationTask = nil
        tapSequenceCount = 0
        tapSequenceID = UUID()
    }

    private func temperature(_ value: Double?) -> String {
        guard let value else { return "--°" }
        return "\(Int(value.rounded()))°"
    }
}
