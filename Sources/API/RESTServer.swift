import Foundation
import NIOCore
import NIOPosix
import NIOHTTP1
import Core
import NetScan
import Engine

public final class RESTServer: @unchecked Sendable {
    public static let shared = RESTServer()
    public private(set) var isRunning = false
    public var port: Int = 8080

    private var channel: Channel?
    private let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    private let store = ScanStore.shared
    private let logger = Logger(category: .config)
    private let lock = NSLock()

    private init() {}

    public func start() throws {
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

        channel = try bootstrap.bind(host: "0.0.0.0", port: port).wait()
        isRunning = true
        logger.notice("REST API started on port \(port)")
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

        switch (method, path) {
        case (.GET, "/health"):
            return (.ok, jsonString(["status": "ok", "version": 1]))

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

    // MARK: - Route Handlers
    private func handleDevices() -> (HTTPResponseStatus, String) {
        guard let devices = latestDevices() else {
            return (.ok, jsonString(["devices": []]))
        }
        return (.ok, jsonString(["devices": devices.map(deviceJSON)]))
    }

    private func handleDevice(ip: String) -> (HTTPResponseStatus, String) {
        guard let devices = latestDevices(),
              let device = devices.first(where: { $0.ip == ip }) else {
            return (.notFound, jsonString(["error": "device not found"]))
        }
        return (.ok, jsonString(deviceJSON(device)))
    }

    private func handleVulnerabilities() -> (HTTPResponseStatus, String) {
        guard let devices = latestDevices() else {
            return (.ok, jsonString(["vulnerabilities": []]))
        }
        let vulns = devices.flatMap { device -> [[String: Any]] in
            device.vulnerabilities.map { vuln in
                var v = vulnJSON(vuln)
                v["device_ip"] = device.ip
                v["device_host"] = device.host ?? ""
                return v
            }
        }
        return (.ok, jsonString(["vulnerabilities": vulns, "count": vulns.count]))
    }

    private func handleScanHistory() -> (HTTPResponseStatus, String) {
        let history = store.loadHistory(limit: 50)
        return (.ok, jsonString(["scans": history.map { summaryJSON($0) }]))
    }

    private func handleScanDetail(scanID: String) -> (HTTPResponseStatus, String) {
        guard let devices = try? store.loadDevices(scanID: scanID) else {
            return (.notFound, jsonString(["error": "scan not found"]))
        }
        return (.ok, jsonString(["scan_id": scanID, "devices": devices.map(deviceJSON)]))
    }

    private func handleStartScan() -> (HTTPResponseStatus, String) {
        Task {
            await runScan()
        }
        return (.accepted, jsonString(["status": "scan started"]))
    }

    private func handleExport(format: String) -> (HTTPResponseStatus, String) {
        guard let devices = latestDevices() else {
            return (.ok, jsonString(["error": "no scan data"]))
        }
        switch format.lowercased() {
        case "json":
            return (.ok, ReportGenerator().generateJSON(devices: devices))
        case "csv":
            return (.ok, ReportGenerator().generateCSV(devices: devices))
        default:
            return (.badRequest, jsonString(["error": "unsupported format: \(format)"]))
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

    // MARK: - JSON Helpers
    private func latestDevices() -> [Device]? {
        let history = store.loadHistory(limit: 1)
        guard let latest = history.first else { return nil }
        return try? store.loadDevices(scanID: latest.scanID)
    }

    private func deviceJSON(_ d: Device) -> [String: Any] {
        [
            "ip": d.ip, "mac": d.mac ?? "", "host": d.host ?? "",
            "os": d.os ?? "", "risk_score": d.riskScore,
            "ports": d.ports.filter { $0.state == .open }.map(portJSON),
            "vulnerabilities": d.vulnerabilities.map(vulnJSON)
        ]
    }

    private func portJSON(_ p: ScanPort) -> [String: Any] {
        ["port": p.number, "service": p.service ?? "", "banner": p.banner ?? ""]
    }

    private func vulnJSON(_ v: Vuln) -> [String: Any] {
        [
            "id": v.id, "severity": v.severity, "description": v.description,
            "recommendation": v.recommendation ?? "", "compliance": v.complianceIDs
        ]
    }

    private func summaryJSON(_ s: ScanSummary) -> [String: Any] {
        [
            "scan_id": s.scanID, "timestamp": ISO8601DateFormatter().string(from: s.timestamp),
            "duration": s.duration, "device_count": s.deviceCount,
            "total_open_ports": s.totalOpenPorts, "total_vulnerabilities": s.totalVulnerabilities,
            "risk_score": s.riskScore
        ]
    }

    private func jsonString(_ obj: [String: Any]) -> String {
        guard let data = try? JSONSerialization.data(withJSONObject: obj, options: [.withoutEscapingSlashes]) else {
            return "{}"
        }
        return String(data: data, encoding: .utf8) ?? "{}"
    }

    private func jsonString(_ arr: [Any]) -> String {
        guard let data = try? JSONSerialization.data(withJSONObject: arr, options: [.withoutEscapingSlashes]) else {
            return "[]"
        }
        return String(data: data, encoding: .utf8) ?? "[]"
    }
}

// MARK: - NIO Channel Handler
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
