import SwiftUI

enum WeatherCoverKey {
    static let enabled = "kassigner.weather.enabled"
    static let cityName = "kassigner.weather.cityName"
    static let latitude = "kassigner.weather.latitude"
    static let longitude = "kassigner.weather.longitude"
    static let temperatureUnit = "kassigner.weather.temperatureUnit"
    static let unlockTarget = "kassigner.weather.unlockTarget"
    static let unlockTapCount = "kassigner.weather.unlockTapCount"
    static let cachedSnapshot = "kassigner.weather.cachedSnapshot"
}

enum WeatherUnlockTarget: String, CaseIterable, Identifiable {
    case location
    case conditionIcon
    case temperature

    var id: String { rawValue }

    var title: String {
        switch self {
        case .location: "Location"
        case .conditionIcon: "Condition Icon"
        case .temperature: "Temperature"
        }
    }
}

private struct WeatherPresentation {
    let symbol: String
    let condition: String
}

private let defaultWeatherPresentation = WeatherPresentation(
    symbol: "cloud.sun.fill",
    condition: "Weather"
)

private let weatherPresentations: [Int: WeatherPresentation] = [
    0: WeatherPresentation(symbol: "sun.max.fill", condition: "Clear"),
    1: WeatherPresentation(symbol: "cloud.sun.fill", condition: "Partly Cloudy"),
    2: WeatherPresentation(symbol: "cloud.sun.fill", condition: "Partly Cloudy"),
    3: WeatherPresentation(symbol: "cloud.fill", condition: "Overcast"),
    45: WeatherPresentation(symbol: "cloud.fog.fill", condition: "Fog"),
    48: WeatherPresentation(symbol: "cloud.fog.fill", condition: "Fog"),
    51: WeatherPresentation(symbol: "cloud.drizzle.fill", condition: "Drizzle"),
    53: WeatherPresentation(symbol: "cloud.drizzle.fill", condition: "Drizzle"),
    55: WeatherPresentation(symbol: "cloud.drizzle.fill", condition: "Drizzle"),
    56: WeatherPresentation(symbol: "cloud.drizzle.fill", condition: "Drizzle"),
    57: WeatherPresentation(symbol: "cloud.drizzle.fill", condition: "Drizzle"),
    61: WeatherPresentation(symbol: "cloud.rain.fill", condition: "Rain"),
    63: WeatherPresentation(symbol: "cloud.rain.fill", condition: "Rain"),
    65: WeatherPresentation(symbol: "cloud.rain.fill", condition: "Rain"),
    66: WeatherPresentation(symbol: "cloud.rain.fill", condition: "Rain"),
    67: WeatherPresentation(symbol: "cloud.rain.fill", condition: "Rain"),
    80: WeatherPresentation(symbol: "cloud.rain.fill", condition: "Rain"),
    81: WeatherPresentation(symbol: "cloud.rain.fill", condition: "Rain"),
    82: WeatherPresentation(symbol: "cloud.rain.fill", condition: "Rain"),
    71: WeatherPresentation(symbol: "cloud.snow.fill", condition: "Snow"),
    73: WeatherPresentation(symbol: "cloud.snow.fill", condition: "Snow"),
    75: WeatherPresentation(symbol: "cloud.snow.fill", condition: "Snow"),
    77: WeatherPresentation(symbol: "cloud.snow.fill", condition: "Snow"),
    85: WeatherPresentation(symbol: "cloud.snow.fill", condition: "Snow"),
    86: WeatherPresentation(symbol: "cloud.snow.fill", condition: "Snow"),
    95: WeatherPresentation(symbol: "cloud.bolt.rain.fill", condition: "Thunderstorms"),
    96: WeatherPresentation(symbol: "cloud.bolt.rain.fill", condition: "Thunderstorms"),
    99: WeatherPresentation(symbol: "cloud.bolt.rain.fill", condition: "Thunderstorms"),
]

private func weatherPresentation(_ code: Int?) -> WeatherPresentation {
    guard let code else { return defaultWeatherPresentation }
    return weatherPresentations[code] ?? defaultWeatherPresentation
}

func weatherSymbol(_ code: Int?) -> String {
    weatherPresentation(code).symbol
}

func conditionName(_ code: Int?) -> String {
    weatherPresentation(code).condition
}

struct WeatherSnapshot: Codable {
    struct Day: Codable, Identifiable {
        let date: Date
        let high: Double
        let low: Double
        let weatherCode: Int

        var id: Date { date }
    }

    let temperature: Double
    let apparentTemperature: Double
    let weatherCode: Int
    let windSpeed: Double
    let daily: [Day]
    let updatedAt: Date
    let latitude: Double
    let longitude: Double
    let temperatureUnit: String
}

struct WeatherLocation: Identifiable, Hashable {
    let id: Int
    let name: String
    let region: String?
    let country: String
    let latitude: Double
    let longitude: Double

    var displayName: String {
        [name, region, country]
            .compactMap { $0 }
            .filter { !$0.isEmpty }
            .joined(separator: ", ")
    }
}

struct ForecastResponse: Decodable {
    struct Current: Decodable {
        let temperature: Double
        let apparentTemperature: Double
        let weatherCode: Int
        let windSpeed: Double

        enum CodingKeys: String, CodingKey {
            case temperature = "temperature_2m"
            case apparentTemperature = "apparent_temperature"
            case weatherCode = "weather_code"
            case windSpeed = "wind_speed_10m"
        }
    }

    struct Daily: Decodable {
        let time: [String]
        let weatherCode: [Int]
        let maximum: [Double]
        let minimum: [Double]

        enum CodingKeys: String, CodingKey {
            case time
            case weatherCode = "weather_code"
            case maximum = "temperature_2m_max"
            case minimum = "temperature_2m_min"
        }
    }

    let current: Current
    let daily: Daily
}

struct GeocodingResponse: Decodable {
    struct Result: Decodable {
        let id: Int
        let name: String
        let latitude: Double
        let longitude: Double
        let country: String
        let admin1: String?
    }

    let results: [Result]?
}

extension JSONDecoder {
    static var weather: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }
}

extension DateFormatter {
    static let weatherDay: DateFormatter = {
        let formatter = DateFormatter()
        formatter.calendar = Calendar(identifier: .gregorian)
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyy-MM-dd"
        return formatter
    }()
}

