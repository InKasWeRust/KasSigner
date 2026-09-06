import SwiftUI

final class WeatherCoverModel: ObservableObject {
    typealias Fetcher = (URLRequest) async throws -> (Data, URLResponse)

    @Published private(set) var snapshot: WeatherSnapshot?
    @Published private(set) var isRefreshing = false
    @Published private(set) var message: String?
    @Published private(set) var searchResults: [WeatherLocation] = []
    @Published private(set) var isSearching = false

    private let defaults: UserDefaults
    private let fetcher: Fetcher
    private var latestSearchID = UUID()

    init(
        defaults: UserDefaults = .standard,
        fetcher: @escaping Fetcher = WeatherCoverModel.liveFetch
    ) {
        self.defaults = defaults
        self.fetcher = fetcher
        snapshot = Self.loadCachedSnapshot(from: defaults)
    }

    func refresh(latitude: Double, longitude: Double, fahrenheit: Bool) async {
        guard !isRefreshing else { return }
        isRefreshing = true
        message = nil
        defer { isRefreshing = false }
        guard let url = Self.forecastURL(latitude: latitude, longitude: longitude, fahrenheit: fahrenheit) else {
            message = "Weather is temporarily unavailable."
            return
        }
        do {
            let (data, response) = try await fetch(url)
            try Self.requireSuccess(response)
            let payload = try JSONDecoder().decode(ForecastResponse.self, from: data)
            let fresh = try Self.snapshot(from: payload, latitude: latitude, longitude: longitude, fahrenheit: fahrenheit)
            snapshot = fresh
            try persist(fresh)
        } catch {
            message = snapshot == nil ? "Weather is temporarily unavailable." : "Unable to refresh. Showing the last update."
        }
    }

    func searchCities(_ query: String) async {
        let searchID = UUID()
        latestSearchID = searchID
        guard let cleaned = Self.searchTerm(query) else {
            searchResults = []
            isSearching = false
            return
        }
        isSearching = true
        defer { finishSearch(searchID) }
        guard let url = Self.searchURL(cleaned) else { return }
        do {
            let (data, response) = try await fetch(url)
            try Self.requireSuccess(response)
            let payload = try JSONDecoder().decode(GeocodingResponse.self, from: data)
            guard latestSearchID == searchID else { return }
            searchResults = Self.locations(from: payload)
        } catch {
            clearSearchResults(ifCurrent: searchID)
        }
    }

    private func finishSearch(_ searchID: UUID) {
        if latestSearchID == searchID { isSearching = false }
    }

    private func clearSearchResults(ifCurrent searchID: UUID) {
        if latestSearchID == searchID { searchResults = [] }
    }

    private func persist(_ value: WeatherSnapshot) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        defaults.set(try encoder.encode(value), forKey: WeatherCoverKey.cachedSnapshot)
    }

    static func loadCachedSnapshot(from defaults: UserDefaults) -> WeatherSnapshot? {
        guard let data = defaults.data(forKey: WeatherCoverKey.cachedSnapshot),
              let cached = try? JSONDecoder.weather.decode(WeatherSnapshot.self, from: data) else { return nil }
        guard cachedMatchesSettings(cached, defaults: defaults) else {
            defaults.removeObject(forKey: WeatherCoverKey.cachedSnapshot)
            return nil
        }
        return cached
    }

    static func cachedMatchesSettings(_ cached: WeatherSnapshot, defaults: UserDefaults) -> Bool {
        cachedLocationMatches(cached, defaults: defaults) && cachedUnitMatches(cached, defaults: defaults)
    }

    static func cachedLocationMatches(_ cached: WeatherSnapshot, defaults: UserDefaults) -> Bool {
        let latitude = storedCoordinate(defaults, key: WeatherCoverKey.latitude, fallback: 40.7128)
        let longitude = storedCoordinate(defaults, key: WeatherCoverKey.longitude, fallback: -74.0060)
        return abs(cached.latitude - latitude) < 0.000_001 && abs(cached.longitude - longitude) < 0.000_001
    }

    static func storedCoordinate(_ defaults: UserDefaults, key: String, fallback: Double) -> Double {
        if let value = defaults.object(forKey: key) as? Double { return value }
        return fallback
    }

    static func cachedUnitMatches(_ cached: WeatherSnapshot, defaults: UserDefaults) -> Bool {
        if let unit = defaults.string(forKey: WeatherCoverKey.temperatureUnit) { return cached.temperatureUnit == unit }
        return cached.temperatureUnit == "fahrenheit"
    }

    static func forecastURL(latitude: Double, longitude: Double, fahrenheit: Bool) -> URL? {
        var components = URLComponents(string: "https://api.open-meteo.com/v1/forecast")
        components?.queryItems = [
            URLQueryItem(name: "latitude", value: String(latitude)),
            URLQueryItem(name: "longitude", value: String(longitude)),
            URLQueryItem(name: "current", value: "temperature_2m,apparent_temperature,weather_code,wind_speed_10m"),
            URLQueryItem(name: "daily", value: "weather_code,temperature_2m_max,temperature_2m_min"),
            URLQueryItem(name: "temperature_unit", value: fahrenheit ? "fahrenheit" : "celsius"),
            URLQueryItem(name: "wind_speed_unit", value: fahrenheit ? "mph" : "kmh"),
            URLQueryItem(name: "timezone", value: "auto"),
            URLQueryItem(name: "forecast_days", value: "6"),
        ]
        return components?.url
    }

    static func snapshot(
        from payload: ForecastResponse,
        latitude: Double,
        longitude: Double,
        fahrenheit: Bool
    ) throws -> WeatherSnapshot {
        let value = WeatherSnapshot(
            temperature: payload.current.temperature,
            apparentTemperature: payload.current.apparentTemperature,
            weatherCode: payload.current.weatherCode,
            windSpeed: payload.current.windSpeed,
            daily: forecastDays(from: payload),
            updatedAt: Date(),
            latitude: latitude,
            longitude: longitude,
            temperatureUnit: fahrenheit ? "fahrenheit" : "celsius"
        )
        guard snapshotIsFinite(value) else { throw URLError(.cannotParseResponse) }
        return value
    }

    static func forecastDays(from payload: ForecastResponse) -> [WeatherSnapshot.Day] {
        let count = [payload.daily.time.count, payload.daily.weatherCode.count, payload.daily.maximum.count, payload.daily.minimum.count].min() ?? 0
        return (0..<count).compactMap { index in
            guard let date = DateFormatter.weatherDay.date(from: payload.daily.time[index]) else { return nil }
            return .init(date: date, high: payload.daily.maximum[index], low: payload.daily.minimum[index], weatherCode: payload.daily.weatherCode[index])
        }
    }

    static func snapshotIsFinite(_ value: WeatherSnapshot) -> Bool {
        value.temperature.isFinite
            && value.apparentTemperature.isFinite
            && value.windSpeed.isFinite
            && value.daily.allSatisfy { $0.high.isFinite && $0.low.isFinite }
    }

    static func searchTerm(_ query: String) -> String? {
        let cleaned = query.trimmingCharacters(in: .whitespacesAndNewlines)
        return cleaned.count >= 2 ? cleaned : nil
    }

    static func searchURL(_ cleaned: String) -> URL? {
        var components = URLComponents(string: "https://geocoding-api.open-meteo.com/v1/search")
        components?.queryItems = [
            URLQueryItem(name: "name", value: cleaned),
            URLQueryItem(name: "count", value: "12"),
            URLQueryItem(name: "language", value: "en"),
            URLQueryItem(name: "format", value: "json"),
        ]
        return components?.url
    }

    static func locations(from payload: GeocodingResponse) -> [WeatherLocation] {
        (payload.results ?? []).compactMap { result in
            guard (-90...90).contains(result.latitude), (-180...180).contains(result.longitude) else { return nil }
            return WeatherLocation(id: result.id, name: result.name, region: result.admin1, country: result.country,
                                   latitude: result.latitude, longitude: result.longitude)
        }
    }

    static func requireSuccess(_ response: URLResponse) throws {
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { throw URLError(.badServerResponse) }
    }

    func clearCache() {
        snapshot = nil
        message = nil
        defaults.removeObject(forKey: WeatherCoverKey.cachedSnapshot)
    }

    static func liveFetch(_ request: URLRequest) async throws -> (Data, URLResponse) {
        try await URLSession.shared.data(for: request)
    }

    private func fetch(_ url: URL) async throws -> (Data, URLResponse) {
        var request = URLRequest(url: url)
        request.timeoutInterval = 12
        request.cachePolicy = .reloadIgnoringLocalCacheData
        let (data, response) = try await fetcher(request)
        guard data.count <= 1_000_000 else {
            throw URLError(.dataLengthExceedsMaximum)
        }
        return (data, response)
    }
}
