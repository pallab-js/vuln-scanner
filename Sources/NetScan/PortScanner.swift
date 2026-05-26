import Foundation
import NIOCore
import NIOPosix
import Core

public struct PortScanner: Sendable {
    private let logger = Logger(category: .scanning)
    private let eventLoopGroup: EventLoopGroup
    private let maxConcurrency: Int

    public init(maxConcurrency: Int = 64) {
        self.eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: min(maxConcurrency / 8, 8))
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
            if attempt > 0 {
                let delay = Double(attempt) * 0.1
                try? await Task.sleep(for: .seconds(delay))
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
            let handler = BannerReadHandler { banner in
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
            if banner.hasPrefix("SSH-") { return "ssh" }
            if banner.contains("FTP") || (banner.contains("220") && banner.localizedCaseInsensitiveContains("ftp")) {
                return "ftp"
            }
            if banner.contains("HTTP/") || banner.contains("Server:") { return "http" }
            if banner.contains("SMTP") || banner.hasPrefix("220 ") { return "smtp" }
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
}

// MARK: - NIO Handlers
private final class BannerReadHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    private let completion: (String?) -> Void
    private var bannerData = Data()

    init(completion: @escaping (String?) -> Void) {
        self.completion = completion
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = unwrapInboundIn(data)
        if let bytes = buffer.readBytes(length: buffer.readableBytes) {
            bannerData.append(contentsOf: bytes)
            if bannerData.count > 1024 {
                let banner = String(data: bannerData.prefix(1024), encoding: .utf8)
                completion(banner)
            }
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        let banner = String(data: bannerData, encoding: .utf8)
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
