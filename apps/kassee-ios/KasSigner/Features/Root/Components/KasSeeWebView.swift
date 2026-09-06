import Foundation
import SwiftUI
import UIKit
@preconcurrency import WebKit

struct KasSeeWebView: UIViewRepresentable {
    let url: URL
    let openMobileSettings: () -> Void
    let resetWebView: () -> Void
    let reportLoadState: (String?) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(
            openMobileSettings: openMobileSettings,
            resetWebView: resetWebView,
            reportLoadState: reportLoadState
        )
    }

    func makeUIView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .default()
        configuration.defaultWebpagePreferences.allowsContentJavaScript = true
        configuration.userContentController.add(context.coordinator, name: Coordinator.messageName)

        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.navigationDelegate = context.coordinator
        webView.uiDelegate = context.coordinator
        webView.isOpaque = false
        webView.backgroundColor = UIColor(red: 8 / 255, green: 12 / 255, blue: 18 / 255, alpha: 1)
        webView.scrollView.backgroundColor = webView.backgroundColor
        webView.allowsBackForwardNavigationGestures = false
#if DEBUG
        if #available(iOS 16.4, *) { webView.isInspectable = true }
#endif
        context.coordinator.allowedPort = url.port
        webView.load(URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData))
        return webView
    }

    func updateUIView(_ webView: WKWebView, context: Context) {
        context.coordinator.openMobileSettings = openMobileSettings
        context.coordinator.resetWebView = resetWebView
        context.coordinator.reportLoadState = reportLoadState
        context.coordinator.allowedPort = url.port
        if webView.url == nil { webView.load(URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData)) }
    }

    static func dismantleUIView(_ webView: WKWebView, coordinator: Coordinator) {
        webView.configuration.userContentController.removeScriptMessageHandler(forName: Coordinator.messageName)
        webView.stopLoading()
        webView.navigationDelegate = nil
        webView.uiDelegate = nil
    }

    final class Coordinator: NSObject, WKNavigationDelegate, WKUIDelegate, WKScriptMessageHandler {
        static let messageName = "kasSignerMobile"
        var openMobileSettings: () -> Void
        var resetWebView: () -> Void
        var reportLoadState: (String?) -> Void
        var allowedPort: Int?
        private var retriedUnhealthyLoad = false

        init(
            openMobileSettings: @escaping () -> Void,
            resetWebView: @escaping () -> Void,
            reportLoadState: @escaping (String?) -> Void
        ) {
            self.openMobileSettings = openMobileSettings
            self.resetWebView = resetWebView
            self.reportLoadState = reportLoadState
        }

        func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
            guard message.name == Self.messageName, let action = message.body as? String else { return }
            if action == "security" { openMobileSettings() }
            else if action == "resetWalletSurface" { resetWebView() }
        }

        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            webView.evaluateJavaScript(Self.mobileBridgeInjection)
            webView.evaluateJavaScript(Self.renderHealthCheck) { [weak self, weak webView] result, error in
                guard let self else { return }
                let failure = error?.localizedDescription ?? (result as? String ?? "")
                if failure.isEmpty {
                    self.retriedUnhealthyLoad = false
                    self.reportLoadState(nil)
                } else if !self.retriedUnhealthyLoad, let webView {
                    self.retriedUnhealthyLoad = true
                    webView.reloadFromOrigin()
                } else {
                    self.reportLoadState("KasSee loaded incompletely: \(failure)")
                }
            }
        }

        func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
            reportLoadState("KasSee navigation failed: \(error.localizedDescription)")
        }

        func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
            reportLoadState("KasSee could not open its local interface: \(error.localizedDescription)")
        }

        func webView(
            _ webView: WKWebView,
            decidePolicyFor navigationAction: WKNavigationAction,
            decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
        ) {
            guard let target = navigationAction.request.url else {
                decisionHandler(.cancel)
                return
            }
            if isLocalKasSee(target) {
                decisionHandler(.allow)
                return
            }
            if target.scheme == "https" || target.scheme == "http" {
                UIApplication.shared.open(target)
            }
            decisionHandler(.cancel)
        }

        func webView(
            _ webView: WKWebView,
            createWebViewWith configuration: WKWebViewConfiguration,
            for navigationAction: WKNavigationAction,
            windowFeatures: WKWindowFeatures
        ) -> WKWebView? {
            guard let target = navigationAction.request.url else { return nil }
            if isLocalKasSee(target) {
                webView.load(navigationAction.request)
            } else if target.scheme == "https" || target.scheme == "http" {
                UIApplication.shared.open(target)
            }
            return nil
        }

        func webView(
            _ webView: WKWebView,
            requestMediaCapturePermissionFor origin: WKSecurityOrigin,
            initiatedByFrame frame: WKFrameInfo,
            type: WKMediaCaptureType,
            decisionHandler: @escaping (WKPermissionDecision) -> Void
        ) {
            let localOrigin = origin.protocol == "http" &&
                (origin.host == "127.0.0.1" || origin.host == "localhost") &&
                (allowedPort == nil || origin.port == allowedPort)
            decisionHandler(localOrigin && type == .camera ? .grant : .deny)
        }

        private func isLocalKasSee(_ url: URL) -> Bool {
            guard url.scheme == "http",
                  url.host == "127.0.0.1" || url.host == "localhost" else { return false }
            return allowedPort == nil || url.port == allowedPort
        }

        private static let renderHealthCheck = """
        (() => {
          const welcome = document.getElementById('screen-welcome');
          const verify = document.getElementById('screen-verify');
          const loadButton = document.getElementById('btn-scan-kpub');
          if (!welcome || !verify || !loadButton) return 'required shared KasSee elements are missing';
          if (getComputedStyle(welcome).display === 'none') return 'welcome screen is hidden';
          if (getComputedStyle(verify).display !== 'none') return 'shared KasSee stylesheet did not apply';
          const viewportWidth = Math.max(document.documentElement.clientWidth, 1);
          if (loadButton.getBoundingClientRect().width < viewportWidth * 0.45) return 'mobile KasSee layout did not apply';
          return '';
        })();
        """

        private static let mobileBridgeInjection = """
        (() => {
          const bridge = {
            openMobileSettings: () => window.webkit?.messageHandlers?.kasSignerMobile?.postMessage('security'),
            resetWalletSurface: () => window.webkit?.messageHandlers?.kasSignerMobile?.postMessage('resetWalletSurface'),
          };
          import('./js/mobile/native_adaptations.js')
            .then(module => module.installMobileAdaptations(bridge))
            .catch(error => console.error('KasSigner mobile adaptations failed', error));
        })();
        """
    }
}
