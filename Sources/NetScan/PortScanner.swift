import Foundation
import NIOCore
import NIOPosix
import Core

public struct PortScanner: Sendable {
    private let logger = Logger(category: .scanning)
    private let eventLoopGroup: EventLoopGroup
    private let maxConcurrency: Int

    private static let sharedELG: EventLoopGroup = {
        MultiThreadedEventLoopGroup(numberOfThreads: 8)
    }()

    public init(maxConcurrency: Int = 64) {
        self.eventLoopGroup = Self.sharedELG
        self.maxConcurrency = min(maxConcurrency, 64)
    }

    public func scan(ip: String, ports: [Int], timeout: TimeInterval = 2.0) async throws -> [ScanPort] {
        logger.notice("Starting port scan on \(ip) for \(ports.count) ports (timeout: \(timeout)s)")

        let gate = ScanGate(limit: maxConcurrency)
        var results: [ScanPort] = []

        try await withThrowingTaskGroup(of: ScanPort?.self) { group in
            for port in ports {
                try Task.checkCancellation()
                await gate.wait()
                let portNum = port

                group.addTask {
                    defer { Task { await gate.signal() } }
                    return await Self.scanPort(
                        ip: ip,
                        port: portNum,
                        timeout: timeout,
                        eventLoopGroup: eventLoopGroup
                    )
                }
            }

            for try await result in group {
                if let scanPort = result {
                    results.append(scanPort)
                }
            }
        }

        results.sort { $0.number < $1.number }
        logger.notice("Port scan complete: \(results.count) open ports on \(ip)")
        return results
    }

    private static func scanPort(
        ip: String,
        port: Int,
        timeout: TimeInterval,
        eventLoopGroup: EventLoopGroup,
        retries: Int = 2
    ) async -> ScanPort {
        let maxRetries = min(max(retries, 0), 3)

        for attempt in 0...maxRetries {
            if Task.isCancelled { return ScanPort(number: port, state: .closed, transport: .tcp) }

            if attempt > 0 {
                try? await Task.sleep(for: .seconds(Double(attempt) * 0.1))
            }

            let result = await attemptConnect(ip: ip, port: port, timeout: timeout, eventLoopGroup: eventLoopGroup)

            switch result {
            case .success(let scanPort):
                return scanPort
            case .failure:
                if attempt == maxRetries {
                    Logger.scanning.debug("Port \(port)/\(ip) closed after \(maxRetries + 1) attempts")
                    return ScanPort(number: port, state: .closed, transport: .tcp)
                }
            }
        }

        return ScanPort(number: port, state: .closed, transport: .tcp)
    }

    private static func attemptConnect(
        ip: String,
        port: Int,
        timeout: TimeInterval,
        eventLoopGroup: EventLoopGroup
    ) async -> Result<ScanPort, Error> {
        let timeoutAmount = TimeAmount.nanoseconds(Int64(timeout * 1_000_000_000))

        let bootstrap = ClientBootstrap(group: eventLoopGroup)
            .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .channelOption(ChannelOptions.connectTimeout, value: timeoutAmount)

        do {
            let channel = try await bootstrap.connect(host: ip, port: port).get()

            let banner = await grabBanner(channel: channel)
            let service = detectService(port: port, banner: banner)

            try? await channel.close().get()

            return .success(ScanPort(
                number: port,
                state: .open,
                transport: .tcp,
                service: service,
                banner: banner
            ))
        } catch {
            return .failure(NetworkError.from(error))
        }
    }
}

// MARK: - Banner Grabbing
extension PortScanner {
    private static func grabBanner(channel: Channel) async -> String? {
        switch channel.remoteAddress?.port {
        case 80, 8080:
            var buffer = channel.allocator.buffer(capacity: 64)
            buffer.writeString("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            try? await channel.writeAndFlush(buffer).get()
        default:
            break
        }

        return await readBanner(channel: channel)
    }

    private static func readBanner(channel: Channel) async -> String? {
        await withCheckedContinuation { continuation in
            let handler = BannerReadHandler(timeout: 0.5) { banner in
                continuation.resume(returning: banner)
            }
            do {
                try channel.pipeline.addHandler(handler).wait()
            } catch {
                continuation.resume(returning: nil)
            }
        }
    }

    private static func detectService(port: Int, banner: String?) -> String? {
        if let banner = banner {
            if banner.hasPrefix("SSH-") {
                let ver = extract(banner, pattern: "SSH-([\\d.]+)")
                return ver.map { "ssh \($0)" } ?? "ssh"
            }
            let lower = banner.lowercased()
            if lower.contains("220") && lower.contains("ftp") {
                let ver = extract(banner, pattern: "FTP[^\\d]*([\\d.]+)")
                return ver.map { "ftp \($0)" } ?? "ftp"
            }
            if lower.contains("http/") || lower.contains("server:") {
                let server = extract(banner, pattern: "(?i)Server:\\s*([^\\r\\n]+)")
                if let s = server { return "http (\(s.trimmingCharacters(in: .whitespaces)))" }
                let ver = extract(banner, pattern: "HTTP/([\\d.]+)")
                return ver.map { "http \($0)" } ?? "http"
            }
            if lower.contains("smtp") || banner.hasPrefix("220 ") {
                let ver = extract(banner, pattern: "ESMTP[^\\d]*([\\w./]+)")
                return ver.map { "smtp \($0)" } ?? "smtp"
            }
            if lower.contains("pop3") || banner.hasPrefix("+OK") {
                let ver = extract(banner, pattern: "POP3[^\\d]*([\\d.]+)")
                return ver.map { "pop3 \($0)" } ?? "pop3"
            }
            if lower.contains("imap") {
                let ver = extract(banner, pattern: "IMAP[^\\d]*([\\d.]+)")
                return ver.map { "imap \($0)" } ?? "imap"
            }
            if lower.contains("mysql") || lower.contains("mariadb") {
                let ver = extract(banner, pattern: "([\\d.]+)")
                return ver.map { "mysql \($0)" } ?? "mysql"
            }
            if lower.contains("rdp") || lower.contains("remote desktop") {
                return "rdp"
            }
        }

        let commonPorts: [Int: String] = [
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 110: "pop3", 143: "imap",
            443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
            3306: "mysql", 3389: "rdp", 5432: "postgresql",
            5900: "vnc", 6379: "redis", 8080: "http-proxy",
            8443: "https-alt", 27017: "mongodb"
        ]
        return commonPorts[port]
    }

    private static func extract(_ banner: String, pattern: String) -> String? {
        let nsString = banner as NSString
        guard let nsRegex = try? NSRegularExpression(pattern: pattern),
              let match = nsRegex.firstMatch(in: banner, range: NSRange(location: 0, length: nsString.length)),
              match.numberOfRanges > 1 else { return nil }
        let range = match.range(at: 1)
        guard range.location != NSNotFound else { return nil }
        return nsString.substring(with: range)
    }
}

// MARK: - NIO Handlers
private final class BannerReadHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    private let completion: (String?) -> Void
    private var bannerData = Data()
    private var didComplete = false
    private let timeout: TimeAmount

    init(timeout: TimeInterval = 1.0, completion: @escaping (String?) -> Void) {
        self.timeout = .nanoseconds(Int64(timeout * 1_000_000_000))
        self.completion = completion
    }

    func channelActive(context: ChannelHandlerContext) {
        context.eventLoop.scheduleTask(in: timeout) { [weak self] in
            self?.finish()
        }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = unwrapInboundIn(data)
        if let bytes = buffer.readBytes(length: buffer.readableBytes) {
            bannerData.append(contentsOf: bytes)
            if bannerData.count >= 1024 {
                finish()
            }
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        finish()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        finish()
    }

    private func finish() {
        guard !didComplete else { return }
        didComplete = true
        let banner = bannerData.isEmpty ? nil : String(data: bannerData.prefix(1024), encoding: .utf8)
        completion(banner)
    }
}

// MARK: - Concurrency Gate
private actor ScanGate {
    private let limit: Int
    private var current = 0
    private var waiters: [CheckedContinuation<Void, Never>] = []

    init(limit: Int) {
        self.limit = limit
    }

    func wait() async {
        if current < limit {
            current += 1
            return
        }
        await withCheckedContinuation { continuation in
            waiters.append(continuation)
        }
    }

    func signal() {
        if let waiter = waiters.first {
            waiters.removeFirst()
            waiter.resume()
        } else {
            current -= 1
        }
    }
}
