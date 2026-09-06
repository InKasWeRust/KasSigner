import Foundation
import SwiftUI

struct RootView: View {
    @StateObject private var webServer = KasSeeLoopbackServer()
    @State private var showingMobileSettings = false
    @State private var webViewGeneration = UUID()
    @State private var webLoadErrorText: String?

    var body: some View {
        Group {
            if let url = webServer.url {
                ZStack {
                    KasSeeWebView(
                        url: url,
                        openMobileSettings: { showingMobileSettings = true },
                        resetWebView: { webViewGeneration = UUID() },
                        reportLoadState: { webLoadErrorText = $0 }
                    )
                    .id(webViewGeneration)
                    if let error = webLoadErrorText { loadFailure(error) }
                }
            } else if let error = webServer.errorText {
                ContentUnavailableView(
                    "KasSee unavailable",
                    systemImage: "exclamationmark.triangle",
                    description: Text(error)
                )
            } else {
                ZStack {
                    Color(red: 8 / 255, green: 12 / 255, blue: 18 / 255)
                        .ignoresSafeArea()
                    ProgressView("Starting KasSee…")
                        .tint(Color(red: 73 / 255, green: 234 / 255, blue: 203 / 255))
                        .foregroundStyle(Color(red: 212 / 255, green: 216 / 255, blue: 222 / 255))
                }
            }
        }
        .task { webServer.startIfNeeded() }
        .sheet(isPresented: $showingMobileSettings) {
            NavigationStack {
                SecuritySettingsView(onHome: { showingMobileSettings = false })
                    .toolbar {
                        ToolbarItem(placement: .topBarTrailing) {
                            Button("Done") { showingMobileSettings = false }
                        }
                    }
            }
        }
    }
    private func loadFailure(_ message: String) -> some View {
        ZStack {
            Color(red: 8 / 255, green: 12 / 255, blue: 18 / 255).ignoresSafeArea()
            VStack(spacing: 14) {
                Image(systemName: "exclamationmark.triangle")
                Text("KasSee failed to render").font(.headline)
                Text(message).font(.footnote).multilineTextAlignment(.center)
                Button("Retry") {
                    webLoadErrorText = nil
                    webViewGeneration = UUID()
                }
                .buttonStyle(.borderedProminent)
            }
            .padding(24)
        }
    }

}
