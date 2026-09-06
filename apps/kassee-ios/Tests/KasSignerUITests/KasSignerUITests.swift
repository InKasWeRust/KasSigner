import XCTest

final class KasSignerUITests: XCTestCase {
    override func setUpWithError() throws {
        continueAfterFailure = false
    }


    func testSharedKasSeeSurfaceRendersStyledAtMobileScale() {
        let app = XCUIApplication()
        app.launchArguments += ["-ui-testing"]
        app.launch()

        let webView = app.webViews.firstMatch
        XCTAssertTrue(webView.waitForExistence(timeout: 20))
        XCTAssertFalse(app.staticTexts["KasSee failed to render"].exists)

        let welcome = webView.staticTexts["Welcome to KasSee"]
        XCTAssertTrue(welcome.waitForExistence(timeout: 20))

        let loadKpub = webView.buttons["Load kpub"]
        XCTAssertTrue(loadKpub.waitForExistence(timeout: 20))
        XCTAssertGreaterThan(loadKpub.frame.width, webView.frame.width * 0.55)

        XCTAssertFalse(webView.staticTexts["Verify Address"].exists)
        XCTAssertFalse(webView.staticTexts["Transaction History"].exists)
    }

    func testApplicationRelaunchSurvivesProcessRecreation() {
        let app = XCUIApplication()
        app.launchArguments += ["-ui-testing"]
        app.launch()
        XCTAssertEqual(app.state, .runningForeground)
        app.terminate()
        XCTAssertEqual(app.state, .notRunning)
        app.launch()
        XCTAssertEqual(app.state, .runningForeground)
    }
}
