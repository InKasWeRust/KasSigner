import Combine
import Foundation
import Network

final class KasSeeLoopbackServer: ObservableObject {
    @Published private(set) var url: URL?
    @Published private(set) var errorText: String?

    private let queue = DispatchQueue(label: "org.kassigner.kassee.loopback", qos: .userInitiated)
    private var listener: NWListener?

    func startIfNeeded() {
        guard listener == nil, url == nil else { return }
        guard let root = Bundle.main.resourceURL?.appendingPathComponent("KasSeeUI", isDirectory: true),
              FileManager.default.fileExists(atPath: root.appendingPathComponent("index.html").path) else {
            errorText = "The bundled KasSee Web interface is missing. Rebuild the iOS target so its KasSee resources are synchronized."
            return
        }

        do {
            let parameters = NWParameters.tcp
            parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
            let listener = try NWListener(using: parameters, on: .any)
            listener.newConnectionHandler = { [weak self] connection in
                self?.serve(connection, from: root)
            }
            listener.stateUpdateHandler = { [weak self, weak listener] state in
                switch state {
                case .ready:
                    guard let port = listener?.port else { return }
                    DispatchQueue.main.async {
                        self?.url = URL(string: "http://127.0.0.1:\(port.rawValue)/index.html")
                        self?.errorText = nil
                    }
                case .failed(let error):
                    DispatchQueue.main.async {
                        self?.errorText = "KasSee local interface failed to start: \(error.localizedDescription)"
                    }
                default:
                    break
                }
            }
            self.listener = listener
            listener.start(queue: queue)
        } catch {
            errorText = "KasSee local interface failed to start: \(error.localizedDescription)"
        }
    }

    deinit {
        listener?.cancel()
    }

    private func serve(_ connection: NWConnection, from root: URL) {
        connection.start(queue: queue)
        receiveRequest(on: connection, from: root, accumulated: Data())
    }

    private func receiveRequest(on connection: NWConnection, from root: URL, accumulated: Data) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 16_384) { [weak self] data, _, isComplete, error in
            guard let self else {
                connection.cancel()
                return
            }
            var request = accumulated
            if let data { request.append(data) }
            if request.range(of: Data("\r\n\r\n".utf8)) != nil {
                self.respond(to: request, on: connection, from: root)
            } else if error == nil, !isComplete, request.count < 65_536 {
                self.receiveRequest(on: connection, from: root, accumulated: request)
            } else {
                self.send(status: "400 Bad Request", mime: "text/plain", body: Data("Bad Request".utf8), on: connection)
            }
        }
    }

    private func respond(to request: Data, on connection: NWConnection, from root: URL) {
        guard let requestText = String(data: request, encoding: .utf8),
              let firstLine = requestText.components(separatedBy: "\r\n").first else {
            send(status: "400 Bad Request", mime: "text/plain", body: Data("Bad Request".utf8), on: connection)
            return
        }
        let parts = firstLine.split(separator: " ", maxSplits: 2).map(String.init)
        guard parts.count == 3, parts[0] == "GET" || parts[0] == "HEAD" else {
            send(status: "405 Method Not Allowed", mime: "text/plain", body: Data("Method Not Allowed".utf8), on: connection)
            return
        }

        guard let decodedPath = Self.normalizedRequestPath(parts[1]) else {
            send(status: "400 Bad Request", mime: "text/plain", body: Data("Bad Request".utf8), on: connection)
            return
        }
        var relativePath = decodedPath.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        if relativePath.isEmpty || decodedPath.hasSuffix("/") {
            relativePath += relativePath.isEmpty ? "index.html" : "/index.html"
        }
        guard !relativePath.contains(".."), !relativePath.contains("\\") else {
            send(status: "403 Forbidden", mime: "text/plain", body: Data("Forbidden".utf8), on: connection)
            return
        }

        let fileURL = root.appendingPathComponent(relativePath).standardizedFileURL
        let rootPrefix = root.standardizedFileURL.path + "/"
        guard fileURL.path.hasPrefix(rootPrefix), FileManager.default.fileExists(atPath: fileURL.path),
              let body = try? Data(contentsOf: fileURL) else {
            send(status: "404 Not Found", mime: "text/plain", body: Data("Not Found".utf8), on: connection)
            return
        }
        send(
            status: "200 OK",
            mime: mimeType(for: fileURL.pathExtension),
            body: body,
            omitBody: parts[0] == "HEAD",
            on: connection
        )
    }

    private func send(
        status: String,
        mime: String,
        body: Data,
        omitBody: Bool = false,
        on connection: NWConnection
    ) {
        var response = Self.httpResponseHeader(
            status: status,
            mime: mime,
            contentLength: body.count
        )
        if !omitBody { response.append(body) }
        connection.send(
            content: response,
            contentContext: .finalMessage,
            isComplete: true,
            completion: .contentProcessed { _ in connection.cancel() }
        )
    }


    static func normalizedRequestPath(_ requestTarget: String) -> String? {
        let rawPath: String
        if let absoluteURL = URL(string: requestTarget), absoluteURL.scheme != nil {
            guard absoluteURL.scheme == "http",
                  absoluteURL.host == "127.0.0.1" || absoluteURL.host == "localhost" else { return nil }
            rawPath = absoluteURL.path.isEmpty ? "/" : absoluteURL.path
        } else {
            rawPath = requestTarget.split(
                separator: "?",
                maxSplits: 1,
                omittingEmptySubsequences: false
            ).first.map(String.init) ?? "/"
        }
        return rawPath.removingPercentEncoding ?? rawPath
    }

    static func httpResponseHeader(status: String, mime: String, contentLength: Int) -> Data {
        let header = [
            "HTTP/1.1 \(status)",
            "Content-Type: \(mime)",
            "Content-Length: \(contentLength)",
            "Cache-Control: no-store",
            "X-Content-Type-Options: nosniff",
            "Connection: close",
            "",
            "",
        ].joined(separator: "\r\n")
        return Data(header.utf8)
    }

    private func mimeType(for extensionName: String) -> String {
        switch extensionName.lowercased() {
        case "html": "text/html; charset=utf-8"
        case "js", "mjs": "text/javascript; charset=utf-8"
        case "css": "text/css; charset=utf-8"
        case "json", "webmanifest": "application/json; charset=utf-8"
        case "wasm": "application/wasm"
        case "png": "image/png"
        case "jpg", "jpeg": "image/jpeg"
        case "svg": "image/svg+xml"
        case "ico": "image/x-icon"
        case "woff": "font/woff"
        case "woff2": "font/woff2"
        default: "application/octet-stream"
        }
    }
}
