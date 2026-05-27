import Foundation
import NIOCore
import NIOPosix
import NIOHTTP1
import Core
import NetScan
import Engine
import os

/// NIO-based REST API server. Binds to 127.0.0.1 by default.
/// Supports optional Bearer token auth via the `apiKey` property.
/// @unchecked Sendable required because Channel is not Sendable.
public final class RESTServer: @unchecked Sendable {
    public static let shared = RESTServer()
    public private(set) var isRunning = false
    public var port: Int = 8080
    public var apiKey: String = ""

    private var channel: Channel?
    private let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    private let store = ScanStore.shared
    private let logger = Logger(category: .config)
    private let lock = OSAllocatedUnfairLock()

    private init() {}

    public func start(host: String = "127.0.0.1") throws {
        lock.lock(); defer { lock.unlock() }
        guard !isRunning else { return }
        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.backlog, value: 256)
            .serverChannelOption(ChannelOptions.socket(.init(SOL_SOCKET), .init(SO_REUSEADDR)), value: 1)
            .childChannelInitializer { channel in
                channel.pipeline.configureHTTPServerPipeline().flatMap {
                    channel.pipeline.addHandler(HTTPHandler(server: self))
                }
            }
            .childChannelOption(ChannelOptions.socket(.init(SOL_SOCKET), .init(SO_REUSEADDR)), value: 1)
            .childChannelOption(ChannelOptions.maxMessagesPerRead, value: 1)

        channel = try bootstrap.bind(host: host, port: port).wait()
        isRunning = true
        logger.notice("REST API started on \(host):\(port)")
    }

    public func stop() {
        lock.lock(); defer { lock.unlock() }
        guard isRunning else { return }
        channel?.close(mode: .all, promise: nil)
        try? group.syncShutdownGracefully()
        isRunning = false
        logger.notice("REST API stopped")
    }

    deinit {
        if isRunning { try? group.syncShutdownGracefully() }
    }

    // MARK: - Request Handler (called from HTTPHandler)
    fileprivate func handle(request: HTTPRequestHead, body: ByteBuffer?) -> (code: HTTPResponseStatus, body: String) {
        let method = request.method
        let uri = request.uri.split(separator: "?").first.map(String.init) ?? request.uri
        let path = uri.hasPrefix("/api/v1") ? String(uri.dropFirst(7)) : uri

        if !apiKey.isEmpty {
            let authHeader = request.headers["Authorization"].first ?? ""
            guard authHeader == "Bearer \(apiKey)" else {
                return (.unauthorized, jsonString(["error": "unauthorized"]))
            }
        }

        switch (method, path) {
        case (.GET, "/health"):
            return (.ok, encodeJSON(HealthResponse(status: "ok", version: 1)))

        case (.GET, "/devices"):
            return handleDevices()

        case (.GET, _) where path.hasPrefix("/devices/"):
            let ip = String(path.dropFirst(9)).removingPercentEncoding ?? ""
            return handleDevice(ip: ip)

        case (.GET, "/vulnerabilities"):
            return handleVulnerabilities()

        case (.GET, "/scans"):
            return handleScanHistory()

        case (.GET, _) where path.hasPrefix("/scans/"):
            let scanID = String(path.dropFirst(7)).removingPercentEncoding ?? ""
            return handleScanDetail(scanID: scanID)

        case (.POST, "/scans"):
            return handleStartScan()

        case (.GET, _) where path.hasPrefix("/export/"):
            let format = String(path.dropFirst(8))
            return handleExport(format: format)

        default:
            return (.notFound, jsonString(["error": "not found"]))
        }
    }

    // MARK: - Codable Response Models
    private struct DevicesResponse: Codable {
        let devices: [JSONDevice]
    }
    private struct VulnsResponse: Codable {
        let vulnerabilities: [JSONVulnWithDevice]
        let count: Int
    }
    private struct JSONVulnWithDevice: Codable {
        let id: String; let severity: Double; let description: String
        let recommendation: String; let compliance: [String]
        let deviceIP: String; let deviceHost: String
    }
    private struct ScansResponse: Codable {
        let scans: [JSONScanSummary]
    }
    private struct ScanDetailResponse: Codable {
        let scanID: String
        let devices: [JSONDevice]
    }
    private struct StatusResponse: Codable {
        let status: String
    }
    private struct ErrorResponse: Codable {
        let error: String
    }
    private struct HealthResponse: Codable {
        let status: String
        let version: Int
    }

    // MARK: - Route Handlers
    private func handleDevices() -> (HTTPResponseStatus, String) {
        guard let devices = latestDevices() else {
            return (.ok, encodeJSON(DevicesResponse(devices: [])))
        }
        return (.ok, encodeJSON(DevicesResponse(devices: devices.map(decodeJSONDevice))))
    }

    private func handleDevice(ip: String) -> (HTTPResponseStatus, String) {
        guard let devices = latestDevices(),
              let device = devices.first(where: { $0.ip == ip }) else {
            return (.notFound, encodeJSON(ErrorResponse(error: "device not found")))
        }
        return (.ok, encodeJSON(decodeJSONDevice(device)))
    }

    private func handleVulnerabilities() -> (HTTPResponseStatus, String) {
        guard let devices = latestDevices() else {
            return (.ok, encodeJSON(VulnsResponse(vulnerabilities: [], count: 0)))
        }
        let vulns = devices.flatMap { device in
            device.vulnerabilities.map { vuln in
                JSONVulnWithDevice(
                    id: vuln.id, severity: vuln.severity, description: vuln.description,
                    recommendation: vuln.recommendation ?? "", compliance: vuln.complianceIDs,
                    deviceIP: device.ip, deviceHost: device.host ?? ""
                )
            }
        }
        return (.ok, encodeJSON(VulnsResponse(vulnerabilities: vulns, count: vulns.count)))
    }

    private func handleScanHistory() -> (HTTPResponseStatus, String) {
        let history = store.loadHistory(limit: 50)
        return (.ok, encodeJSON(ScansResponse(scans: history.map(decodeJSONSummary))))
    }

    private func handleScanDetail(scanID: String) -> (HTTPResponseStatus, String) {
        guard let devices = try? store.loadDevices(scanID: scanID) else {
            return (.notFound, encodeJSON(ErrorResponse(error: "scan not found")))
        }
        return (.ok, encodeJSON(ScanDetailResponse(scanID: scanID, devices: devices.map(decodeJSONDevice))))
    }

    private func handleStartScan() -> (HTTPResponseStatus, String) {
        Task {
            await runScan()
        }
        return (.accepted, encodeJSON(StatusResponse(status: "scan started")))
    }

    private func handleExport(format: String) -> (HTTPResponseStatus, String) {
        guard let devices = latestDevices() else {
            return (.ok, encodeJSON(ErrorResponse(error: "no scan data")))
        }
        switch format.lowercased() {
        case "json":
            return (.ok, ReportGenerator().generateJSON(devices: devices))
        case "csv":
            return (.ok, ReportGenerator().generateCSV(devices: devices))
        default:
            return (.badRequest, encodeJSON(ErrorResponse(error: "unsupported format: \(format)")))
        }
    }

    @MainActor
    private func runScan() async {
        let discovery = NetworkDiscovery()
        let scanner = PortScanner()
        let mapper = VulnMapper()
        let osFP = OSFingerprinter()
        let customRules = CustomRulesStore.shared.load()
        do {
            let discovered = try await discovery.scanSubnet(timeout: 30)
            var scanned: [Device] = []
            for var device in discovered {
                let ports = try await scanner.scan(ip: device.ip, ports: Array(1...1024), timeout: 2)
                let os = osFP.infer(ports: ports)
                device = Device(ip: device.ip, mac: device.mac, host: device.host, os: os ?? device.os, ports: ports)
                let vulns = mapper.map(device: device, customRules: customRules)
                device = Device(ip: device.ip, mac: device.mac, host: device.host, os: device.os, ports: ports, vulnerabilities: vulns)
                scanned.append(device)
            }
            let result = ScanResult(devices: scanned, scanDuration: 0, totalPortsScanned: 1024)
            _ = try? store.save(scanResult: result, config: .default, duration: 0)
        } catch {
            logger.error("API scan failed: \(error.localizedDescription)")
        }
    }

    // MARK: - Codable JSON Models
    private struct JSONDevice: Codable {
        let ip: String; let mac: String; let host: String; let os: String
        let riskScore: Double; let ports: [JSONPort]; let vulnerabilities: [JSONVuln]
    }
    private struct JSONPort: Codable {
        let port: Int; let service: String; let banner: String
    }
    private struct JSONVuln: Codable {
        let id: String; let severity: Double; let description: String
        let recommendation: String; let compliance: [String]
    }
    private struct JSONScanSummary: Codable {
        let scanID: String; let timestamp: String; let duration: TimeInterval
        let deviceCount: Int; let totalOpenPorts: Int; let totalVulnerabilities: Int; let riskScore: Double
    }

    private let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.outputFormatting = [.withoutEscapingSlashes, .sortedKeys]
        return e
    }()

    private func latestDevices() -> [Device]? {
        let history = store.loadHistory(limit: 1)
        guard let latest = history.first else { return nil }
        return try? store.loadDevices(scanID: latest.scanID)
    }

    private func encodeJSON<T: Encodable>(_ value: T) -> String {
        guard let data = try? encoder.encode(value) else { return "{}" }
        return String(data: data, encoding: .utf8) ?? "{}"
    }

    private func decodeJSONDevice(_ d: Device) -> JSONDevice {
        JSONDevice(
            ip: d.ip, mac: d.mac ?? "", host: d.host ?? "", os: d.os ?? "",
            riskScore: d.riskScore,
            ports: d.ports.filter { $0.state == .open }.map {
                JSONPort(port: $0.number, service: $0.service ?? "", banner: $0.banner ?? "")
            },
            vulnerabilities: d.vulnerabilities.map {
                JSONVuln(id: $0.id, severity: $0.severity, description: $0.description, recommendation: $0.recommendation ?? "", compliance: $0.complianceIDs)
            }
        )
    }

    private func decodeJSONSummary(_ s: ScanSummary) -> JSONScanSummary {
        JSONScanSummary(
            scanID: s.scanID, timestamp: ISO8601DateFormatter().string(from: s.timestamp),
            duration: s.duration, deviceCount: s.deviceCount,
            totalOpenPorts: s.totalOpenPorts, totalVulnerabilities: s.totalVulnerabilities,
            riskScore: s.riskScore
        )
    }

    private func jsonString(_ value: some Encodable) -> String {
        encodeJSON(value)
    }
}

// MARK: - NIO Channel Handler
/// Decodes HTTP requests and routes them to RESTServer.handle().
/// @unchecked Sendable is required for NIO channel handlers (always run on a single EL).
private final class HTTPHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart
    private let server: RESTServer

    init(server: RESTServer) {
        self.server = server
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let req = unwrapInboundIn(data)
        switch req {
        case .head(let head):
            let (status, body) = server.handle(request: head, body: nil)
            var buffer = context.channel.allocator.buffer(capacity: body.utf8.count)
            buffer.writeString(body)
            var headers = HTTPHeaders()
            headers.add(name: "Content-Type", value: "application/json")
            headers.add(name: "Content-Length", value: String(buffer.readableBytes))
            let responseHead = HTTPResponseHead(version: head.version, status: status, headers: headers)
            let bodyPart: HTTPServerResponsePart = .body(.byteBuffer(buffer))
            context.write(wrapOutboundOut(.head(responseHead)), promise: nil)
            context.write(wrapOutboundOut(bodyPart), promise: nil)
            let endPart: HTTPServerResponsePart = .end(nil)
            context.writeAndFlush(wrapOutboundOut(endPart), promise: nil)
        case .body, .end:
            break
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: any Error) {
        context.close(promise: nil)
    }
}
