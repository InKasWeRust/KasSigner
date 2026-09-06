import Foundation
import LocalAuthentication
import XCTest
@testable import KasSigner

@MainActor
final class KasSignerAppTests: XCTestCase {
    private func defaultsSuite(_ label: String) -> (String, UserDefaults) {
        let name = "org.kassigner.tests.\(label).\(UUID().uuidString)"
        guard let defaults = UserDefaults(suiteName: name) else {
            fatalError("Unable to create isolated UserDefaults suite")
        }
        defaults.removePersistentDomain(forName: name)
        return (name, defaults)
    }

    private func httpResponse(statusCode: Int, url: URL = URL(string: "https://example.invalid/")!) -> HTTPURLResponse {
        guard let response = HTTPURLResponse(url: url, statusCode: statusCode, httpVersion: nil, headerFields: nil) else {
            fatalError("Unable to create HTTPURLResponse")
        }
        return response
    }

    private func forecastData() -> Data {
        Data(
            """
            {
              "current": {
                "temperature_2m": 72.0,
                "apparent_temperature": 71.0,
                "weather_code": 1,
                "wind_speed_10m": 5.0
              },
              "daily": {
                "time": ["2026-09-02", "2026-09-03"],
                "weather_code": [1, 61],
                "temperature_2m_max": [75.0, 70.0],
                "temperature_2m_min": [62.0, 58.0]
              }
            }
            """.utf8
        )
    }

    private func paddedForecastData(count: Int) -> Data {
        var data = forecastData()
        precondition(data.count <= count)
        data.append(Data(repeating: 0x20, count: count - data.count))
        return data
    }

    private func geocodingData() -> Data {
        Data(
            """
            {
              "results": [
                {
                  "id": 5128581,
                  "name": "New York",
                  "latitude": 40.7128,
                  "longitude": -74.0060,
                  "country": "United States",
                  "admin1": "New York"
                }
              ]
            }
            """.utf8
        )
    }

    private func weatherSnapshot(
        temperature: Double = 72,
        apparentTemperature: Double = 71,
        windSpeed: Double = 5,
        dailyHigh: Double = 75,
        dailyLow: Double = 62,
        latitude: Double = 40.7128,
        longitude: Double = -74.0060,
        unit: String = "fahrenheit"
    ) -> WeatherSnapshot {
        WeatherSnapshot(
            temperature: temperature,
            apparentTemperature: apparentTemperature,
            weatherCode: 1,
            windSpeed: windSpeed,
            daily: [
                WeatherSnapshot.Day(
                    date: Date(timeIntervalSince1970: 1_700_000_000),
                    high: dailyHigh,
                    low: dailyLow,
                    weatherCode: 1
                )
            ],
            updatedAt: Date(timeIntervalSince1970: 1_700_000_000),
            latitude: latitude,
            longitude: longitude,
            temperatureUnit: unit
        )
    }

    private func persistSnapshot(_ snapshot: WeatherSnapshot, defaults: UserDefaults) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        defaults.set(try encoder.encode(snapshot), forKey: WeatherCoverKey.cachedSnapshot)
    }

    private func authenticationSession(
        canEvaluate: Bool = true,
        availabilityError: String? = nil,
        evaluate: @escaping (String) async throws -> Bool = { _ in true }
    ) -> AppLockService.AuthenticationSession {
        AppLockService.AuthenticationSession(
            canEvaluate: { (canEvaluate, availabilityError) },
            evaluate: evaluate
        )
    }


    func testKasSeeLoopbackHTTPFramingAndRequestTargets() {
        let header = String(
            decoding: KasSeeLoopbackServer.httpResponseHeader(
                status: "200 OK",
                mime: "text/css; charset=utf-8",
                contentLength: 123
            ),
            as: UTF8.self
        )
        XCTAssertTrue(header.hasSuffix("\r\n\r\n"))
        XCTAssertEqual(header.components(separatedBy: "\r\n\r\n").count, 2)
        XCTAssertTrue(header.contains("Content-Type: text/css; charset=utf-8\r\n"))
        XCTAssertTrue(header.contains("Content-Length: 123\r\n"))

        XCTAssertEqual(
            KasSeeLoopbackServer.normalizedRequestPath("/css/app.css?v=102"),
            "/css/app.css"
        )
        XCTAssertEqual(
            KasSeeLoopbackServer.normalizedRequestPath("http://127.0.0.1:49152/css/app.css?v=102"),
            "/css/app.css"
        )
        XCTAssertNil(
            KasSeeLoopbackServer.normalizedRequestPath("https://example.invalid/css/app.css")
        )
    }

    func testAppLockImmediateBackgroundTransitionRelocks() async {
        let (suite, defaults) = defaultsSuite("lock.immediate")
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set(true, forKey: "kassigner.security.appLockEnabled")
        defaults.set("immediately", forKey: "kassigner.security.lockDelay")
        let lock = AppLockService(
            defaults: defaults,
            authenticationSessionFactory: { self.authenticationSession() }
        )
        await lock.unlock()
        XCTAssertFalse(lock.isLocked)
        lock.sceneDidEnterBackground()
        XCTAssertTrue(lock.isLocked)
        lock.sceneDidBecomeActive()
        XCTAssertTrue(lock.isLocked)
    }

    func testAppLockDefaultsAndDisabledStateClearPrivacyCover() {
        let (suite, defaults) = defaultsSuite("lock.defaults")
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set(true, forKey: "kassigner.security.decoyLaunchScreenEnabled")

        let lock = AppLockService(defaults: defaults)

        XCTAssertFalse(lock.isEnabled)
        XCTAssertFalse(lock.isLocked)
        XCTAssertFalse(lock.isAuthenticating)
        XCTAssertFalse(lock.isPrivacyCoverSuspendedForSession)
        XCTAssertTrue(lock.hideAppSwitcherPreview)
        XCTAssertFalse(defaults.bool(forKey: "kassigner.security.decoyLaunchScreenEnabled"))
    }

    func testAppLockEnableDisableUnlockAndPrivacyCoverTransitions() async {
        let (suite, defaults) = defaultsSuite("lock.transitions")
        defer { defaults.removePersistentDomain(forName: suite) }
        let factory = { self.authenticationSession() }
        let lock = AppLockService(defaults: defaults, authenticationSessionFactory: factory)

        let enabled = await lock.enableAppLock()
        XCTAssertTrue(enabled)
        XCTAssertTrue(lock.isEnabled)
        XCTAssertFalse(lock.isLocked)

        lock.sceneDidEnterBackground()
        XCTAssertTrue(lock.isLocked)
        await lock.unlock()
        XCTAssertFalse(lock.isLocked)

        lock.sceneDidEnterBackground()
        let unlockedFromCover = await lock.unlockFromPrivacyCover()
        XCTAssertTrue(unlockedFromCover)
        XCTAssertFalse(lock.isLocked)
        let alreadyUnlockedFromCover = await lock.unlockFromPrivacyCover()
        XCTAssertTrue(alreadyUnlockedFromCover)

        lock.suspendPrivacyCoverForCurrentSession()
        XCTAssertTrue(lock.isPrivacyCoverSuspendedForSession)
        lock.sceneDidEnterBackground()
        XCTAssertFalse(lock.isPrivacyCoverSuspendedForSession)

        defaults.set(true, forKey: "kassigner.security.decoyLaunchScreenEnabled")
        let disabled = await lock.disableAppLock()
        XCTAssertTrue(disabled)
        XCTAssertFalse(lock.isEnabled)
        XCTAssertFalse(lock.isLocked)
        XCTAssertFalse(defaults.bool(forKey: "kassigner.security.decoyLaunchScreenEnabled"))
        let disabledCoverUnlock = await lock.unlockFromPrivacyCover()
        XCTAssertFalse(disabledCoverUnlock)
    }

    func testAppLockFailedAuthenticationDoesNotChangeProtectedState() async {
        let (suite, defaults) = defaultsSuite("lock.failed")
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set(true, forKey: "kassigner.security.appLockEnabled")
        let lock = AppLockService(
            defaults: defaults,
            authenticationSessionFactory: {
                self.authenticationSession(evaluate: { _ in false })
            }
        )

        let disabled = await lock.disableAppLock()
        XCTAssertFalse(disabled)
        XCTAssertTrue(lock.isEnabled)
        XCTAssertTrue(lock.isLocked)
        await lock.unlock()
        XCTAssertTrue(lock.isLocked)
        let disabledCoverUnlock = await lock.unlockFromPrivacyCover()
        XCTAssertFalse(disabledCoverUnlock)
        XCTAssertTrue(lock.isLocked)
    }

    func testAppLockAuthenticationAvailabilityAndFailureMessages() async {
        let (suite, defaults) = defaultsSuite("lock.errors")
        defer { defaults.removePersistentDomain(forName: suite) }

        let unavailable = AppLockService(
            defaults: defaults,
            authenticationSessionFactory: {
                self.authenticationSession(canEvaluate: false, availabilityError: "Authentication unavailable")
            }
        )
        let unavailableAuthorization = await unavailable.authorizePrivacyCoverChange()
        XCTAssertFalse(unavailableAuthorization)
        XCTAssertEqual(unavailable.authenticationError, "Authentication unavailable")
        XCTAssertFalse(unavailable.isAuthenticating)

        let failed = AppLockService(
            defaults: defaults,
            authenticationSessionFactory: {
                self.authenticationSession(evaluate: { _ in
                    throw NSError(
                        domain: LAError.errorDomain,
                        code: LAError.Code.authenticationFailed.rawValue,
                        userInfo: [NSLocalizedDescriptionKey: "Authentication failed"]
                    )
                })
            }
        )
        let failedAuthorization = await failed.authorizePrivacyCoverChange()
        XCTAssertFalse(failedAuthorization)
        XCTAssertNotNil(failed.authenticationError)
        XCTAssertFalse(failed.isAuthenticating)
    }

    func testAppLockCancellationErrorsRemainNonDiagnostic() async {
        for code in [LAError.Code.userCancel, .appCancel, .systemCancel] {
            let (suite, defaults) = defaultsSuite("lock.cancel.\(code.rawValue)")
            defer { defaults.removePersistentDomain(forName: suite) }
            let lock = AppLockService(
                defaults: defaults,
                authenticationSessionFactory: {
                    self.authenticationSession(evaluate: { _ in
                        throw NSError(
                            domain: LAError.errorDomain,
                            code: code.rawValue,
                            userInfo: [NSLocalizedDescriptionKey: "Cancelled"]
                        )
                    })
                }
            )
            let authorization = await lock.authorizePrivacyCoverChange()
            XCTAssertFalse(authorization)
            XCTAssertNil(lock.authenticationError)
        }
    }

    func testAppLockAuthenticationIsSingleFlightAndResetsBusyState() async throws {
        let (suite, defaults) = defaultsSuite("lock.singleflight")
        defer { defaults.removePersistentDomain(forName: suite) }
        let lock = AppLockService(
            defaults: defaults,
            authenticationSessionFactory: {
                self.authenticationSession(evaluate: { _ in
                    try await Task.sleep(for: .milliseconds(80))
                    return true
                })
            }
        )

        let first = Task { @MainActor in await lock.enableAppLock() }
        try await Task.sleep(for: .milliseconds(15))
        XCTAssertTrue(lock.isAuthenticating)
        let second = await lock.enableAppLock()
        XCTAssertFalse(second)
        let firstResult = await first.value
        XCTAssertTrue(firstResult)
        XCTAssertFalse(lock.isAuthenticating)
    }

    func testAppLockDelayedRelockUsesExactConfiguredBoundary() async {
        let (suite, defaults) = defaultsSuite("lock.delay")
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set(true, forKey: "kassigner.security.appLockEnabled")
        defaults.set("oneMinute", forKey: "kassigner.security.lockDelay")
        var now = Date(timeIntervalSince1970: 1_700_000_000)
        let lock = AppLockService(
            defaults: defaults,
            authenticationSessionFactory: { self.authenticationSession() },
            now: { now }
        )

        await lock.unlock()
        XCTAssertFalse(lock.isLocked)
        lock.sceneDidEnterBackground()
        XCTAssertFalse(lock.isLocked)
        now = now.addingTimeInterval(60)
        lock.sceneDidBecomeActive()
        XCTAssertTrue(lock.isLocked)
    }

    func testWeatherCoverPreferenceContractAndUnlockTargets() {
        XCTAssertEqual(WeatherCoverKey.enabled, "kassigner.weather.enabled")
        XCTAssertEqual(WeatherCoverKey.cityName, "kassigner.weather.cityName")
        XCTAssertEqual(WeatherCoverKey.latitude, "kassigner.weather.latitude")
        XCTAssertEqual(WeatherCoverKey.longitude, "kassigner.weather.longitude")
        XCTAssertEqual(WeatherCoverKey.temperatureUnit, "kassigner.weather.temperatureUnit")
        XCTAssertEqual(WeatherCoverKey.unlockTarget, "kassigner.weather.unlockTarget")
        XCTAssertEqual(WeatherCoverKey.unlockTapCount, "kassigner.weather.unlockTapCount")
        XCTAssertEqual(WeatherCoverKey.cachedSnapshot, "kassigner.weather.cachedSnapshot")

        XCTAssertEqual(WeatherUnlockTarget.allCases, [.location, .conditionIcon, .temperature])
        XCTAssertEqual(WeatherUnlockTarget.location.title, "Location")
        XCTAssertEqual(WeatherUnlockTarget.conditionIcon.title, "Condition Icon")
        XCTAssertEqual(WeatherUnlockTarget.temperature.title, "Temperature")
    }

    func testWeatherPresentationHelpersCoverOpenMeteoCodes() {
        let cases: [(Int?, String, String)] = [
            (0, "sun.max.fill", "Clear"),
            (1, "cloud.sun.fill", "Partly Cloudy"),
            (2, "cloud.sun.fill", "Partly Cloudy"),
            (3, "cloud.fill", "Overcast"),
            (45, "cloud.fog.fill", "Fog"),
            (48, "cloud.fog.fill", "Fog"),
            (51, "cloud.drizzle.fill", "Drizzle"),
            (57, "cloud.drizzle.fill", "Drizzle"),
            (61, "cloud.rain.fill", "Rain"),
            (82, "cloud.rain.fill", "Rain"),
            (71, "cloud.snow.fill", "Snow"),
            (86, "cloud.snow.fill", "Snow"),
            (95, "cloud.bolt.rain.fill", "Thunderstorms"),
            (99, "cloud.bolt.rain.fill", "Thunderstorms"),
            (nil, "cloud.sun.fill", "Weather"),
            (999, "cloud.sun.fill", "Weather"),
        ]

        for (code, expectedSymbol, expectedName) in cases {
            XCTAssertEqual(weatherSymbol(code), expectedSymbol)
            XCTAssertEqual(conditionName(code), expectedName)
        }
    }

    func testWeatherCodecHelpersMatchPersistedAndForecastFormats() throws {
        let snapshot = weatherSnapshot()
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(snapshot)
        let decoded = try JSONDecoder.weather.decode(WeatherSnapshot.self, from: data)
        XCTAssertEqual(decoded.temperatureUnit, snapshot.temperatureUnit)
        XCTAssertEqual(decoded.updatedAt.timeIntervalSince1970, snapshot.updatedAt.timeIntervalSince1970, accuracy: 1)

        let day = try XCTUnwrap(DateFormatter.weatherDay.date(from: "2026-09-02"))
        XCTAssertEqual(DateFormatter.weatherDay.string(from: day), "2026-09-02")
    }

    func testWeatherCacheRequiresBothCoordinatesAndTemperatureUnit() throws {
        let (suite, defaults) = defaultsSuite("weather.cache")
        defer { defaults.removePersistentDomain(forName: suite) }
        let snapshot = weatherSnapshot()
        defaults.set(40.7128, forKey: WeatherCoverKey.latitude)
        defaults.set(-74.0060, forKey: WeatherCoverKey.longitude)
        defaults.set("fahrenheit", forKey: WeatherCoverKey.temperatureUnit)

        XCTAssertTrue(WeatherCoverModel.cachedMatchesSettings(snapshot, defaults: defaults))

        defaults.set(41.0, forKey: WeatherCoverKey.latitude)
        XCTAssertFalse(WeatherCoverModel.cachedMatchesSettings(snapshot, defaults: defaults))
        XCTAssertFalse(WeatherCoverModel.cachedLocationMatches(snapshot, defaults: defaults))

        defaults.set(40.7128, forKey: WeatherCoverKey.latitude)
        defaults.set(-73.0, forKey: WeatherCoverKey.longitude)
        XCTAssertFalse(WeatherCoverModel.cachedLocationMatches(snapshot, defaults: defaults))

        defaults.set(-74.0060, forKey: WeatherCoverKey.longitude)
        defaults.set("celsius", forKey: WeatherCoverKey.temperatureUnit)
        XCTAssertFalse(WeatherCoverModel.cachedMatchesSettings(snapshot, defaults: defaults))
        XCTAssertFalse(WeatherCoverModel.cachedUnitMatches(snapshot, defaults: defaults))

        defaults.removeObject(forKey: WeatherCoverKey.temperatureUnit)
        XCTAssertTrue(WeatherCoverModel.cachedUnitMatches(snapshot, defaults: defaults))
        XCTAssertFalse(WeatherCoverModel.cachedUnitMatches(weatherSnapshot(unit: "celsius"), defaults: defaults))

        try persistSnapshot(snapshot, defaults: defaults)
        defaults.set(41.0, forKey: WeatherCoverKey.latitude)
        XCTAssertNil(WeatherCoverModel.loadCachedSnapshot(from: defaults))
        XCTAssertNil(defaults.data(forKey: WeatherCoverKey.cachedSnapshot))
    }

    func testWeatherFiniteValidationRejectsEachNonFiniteField() {
        XCTAssertTrue(WeatherCoverModel.snapshotIsFinite(weatherSnapshot()))
        XCTAssertFalse(WeatherCoverModel.snapshotIsFinite(weatherSnapshot(temperature: .nan)))
        XCTAssertFalse(WeatherCoverModel.snapshotIsFinite(weatherSnapshot(apparentTemperature: .infinity)))
        XCTAssertFalse(WeatherCoverModel.snapshotIsFinite(weatherSnapshot(windSpeed: -.infinity)))
        XCTAssertFalse(WeatherCoverModel.snapshotIsFinite(weatherSnapshot(dailyHigh: .nan)))
        XCTAssertFalse(WeatherCoverModel.snapshotIsFinite(weatherSnapshot(dailyLow: .nan)))
    }

    func testWeatherSearchBoundaryAndHTTPStatusContract() throws {
        XCTAssertNil(WeatherCoverModel.searchTerm("a"))
        XCTAssertEqual(WeatherCoverModel.searchTerm(" ab "), "ab")

        let response200 = httpResponse(statusCode: 200)
        XCTAssertNoThrow(try WeatherCoverModel.requireSuccess(response200))
        XCTAssertThrowsError(try WeatherCoverModel.requireSuccess(httpResponse(statusCode: 201)))
    }

    func testWeatherModelRefreshTracksStateAndPersistsSuccess() async {
        let (suite, defaults) = defaultsSuite("weather.refresh")
        defer { defaults.removePersistentDomain(forName: suite) }
        var model: WeatherCoverModel!
        var observedRefreshing = false
        model = WeatherCoverModel(defaults: defaults, fetcher: { request in
            observedRefreshing = model.isRefreshing
            XCTAssertEqual(request.timeoutInterval, 12)
            XCTAssertEqual(request.cachePolicy, .reloadIgnoringLocalCacheData)
            return (self.forecastData(), self.httpResponse(statusCode: 200, url: request.url!))
        })

        XCTAssertFalse(model.isRefreshing)
        XCTAssertFalse(model.isSearching)
        await model.refresh(latitude: 40.7128, longitude: -74.0060, fahrenheit: true)

        XCTAssertTrue(observedRefreshing)
        XCTAssertFalse(model.isRefreshing)
        XCTAssertNil(model.message)
        XCTAssertEqual(model.snapshot?.temperatureUnit, "fahrenheit")
        XCTAssertNotNil(defaults.data(forKey: WeatherCoverKey.cachedSnapshot))
    }

    func testWeatherModelRefreshFailureUsesEmptyCacheMessage() async {
        let (suite, defaults) = defaultsSuite("weather.refresh.error")
        defer { defaults.removePersistentDomain(forName: suite) }
        let model = WeatherCoverModel(defaults: defaults, fetcher: { _ in
            throw URLError(.notConnectedToInternet)
        })

        await model.refresh(latitude: 40.7128, longitude: -74.0060, fahrenheit: true)
        XCTAssertNil(model.snapshot)
        XCTAssertEqual(model.message, "Weather is temporarily unavailable.")
        XCTAssertFalse(model.isRefreshing)
    }

    func testWeatherModelAcceptsExactMaximumResponseSize() async {
        let (suite, defaults) = defaultsSuite("weather.size")
        defer { defaults.removePersistentDomain(forName: suite) }
        let exactMaximum = paddedForecastData(count: 1_000_000)
        XCTAssertEqual(exactMaximum.count, 1_000_000)
        let model = WeatherCoverModel(defaults: defaults, fetcher: { request in
            (exactMaximum, self.httpResponse(statusCode: 200, url: request.url!))
        })

        await model.refresh(latitude: 40.7128, longitude: -74.0060, fahrenheit: true)
        XCTAssertNotNil(model.snapshot)
        XCTAssertNil(model.message)
    }

    func testWeatherCitySearchTracksBusyStateAndCurrentResults() async {
        let (suite, defaults) = defaultsSuite("weather.search")
        defer { defaults.removePersistentDomain(forName: suite) }
        var model: WeatherCoverModel!
        var observedSearching = false
        var shouldFail = false
        model = WeatherCoverModel(defaults: defaults, fetcher: { request in
            observedSearching = observedSearching || model.isSearching
            if shouldFail { throw URLError(.cannotConnectToHost) }
            return (self.geocodingData(), self.httpResponse(statusCode: 200, url: request.url!))
        })

        XCTAssertFalse(model.isSearching)
        await model.searchCities("New")
        XCTAssertTrue(observedSearching)
        XCTAssertFalse(model.isSearching)
        XCTAssertEqual(model.searchResults.map(\.name), ["New York"])

        shouldFail = true
        await model.searchCities("Los")
        XCTAssertFalse(model.isSearching)
        XCTAssertTrue(model.searchResults.isEmpty)

        await model.searchCities("x")
        XCTAssertFalse(model.isSearching)
        XCTAssertTrue(model.searchResults.isEmpty)
    }

    func testNativeAppearancePreferenceRemainsShellOnly() {
        let defaults = UserDefaults.standard
        let key = "kassigner.appearanceTheme.v1"
        let previous = defaults.object(forKey: key)
        defer {
            if let previous { defaults.set(previous, forKey: key) } else { defaults.removeObject(forKey: key) }
        }
        defaults.set("light", forKey: key)
        XCTAssertEqual(AppPreferences().appearanceTheme, .light)
    }
}
