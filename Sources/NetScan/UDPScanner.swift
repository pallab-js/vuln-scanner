import Foundation
import NIOCore
import NIOPosix
import Core

public struct UDPScanner: Sendable {
    private let logger = Logger(category: .scanning)
    private let eventLoopGroup: EventLoopGroup
    private let maxConcurrency: Int

    private static let sharedELG: EventLoopGroup = {
        MultiThreadedEventLoopGroup(numberOfThreads: 4)
    }()

    public init(eventLoopGroup: EventLoopGroup? = nil, maxConcurrency: Int = 32) {
        self.eventLoopGroup = eventLoopGroup ?? Self.sharedELG
        self.maxConcurrency = min(maxConcurrency, 64)
    }

    public func scan(ip: String, ports: [Int], timeout: TimeInterval = 2.0) async throws -> [ScanPort] {
        logger.notice("Starting UDP scan on \(ip) for \(ports.count) ports")

        let gate = ScanGateUD(limit: maxConcurrency)
        var results: [ScanPort] = []

        try await withThrowingTaskGroup(of: ScanPort.self) { group in
            for port in ports {
                try Task.checkCancellation()
                await gate.wait()
                let portNum = port

                group.addTask {
                    defer { Task { await gate.signal() } }
                    return await self.scanPort(ip: ip, port: portNum, timeout: timeout)
                }
            }

            for try await result in group {
                results.append(result)
            }
        }

        results.sort { $0.number < $1.number }
        let open = results.filter { $0.state == .open }.count
        logger.notice("UDP scan complete: \(open) open ports on \(ip)")
        return results
    }

    private func scanPort(ip: String, port: Int, timeout: TimeInterval) async -> ScanPort {
        let address: SocketAddress
        do {
            address = try SocketAddress(ipAddress: ip, port: port)
        } catch {
            return ScanPort(number: port, state: .closed, transport: .udp)
        }

        let bootstrap = DatagramBootstrap(group: eventLoopGroup)
            .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)

        do {
            let channel = try await bootstrap.bind(host: "0.0.0.0", port: 0).get()
            let hasResponse = try await channel.eventLoop.flatSubmit { () -> EventLoopFuture<Bool> in
                let promise = channel.eventLoop.makePromise(of: Bool.self)
                let handler = UDPResponseHandler(promise: promise)
                let scheduled = channel.eventLoop.scheduleTask(in: .nanoseconds(Int64(timeout * 1_000_000_000))) {
                    promise.succeed(false)
                }

                promise.futureResult.whenComplete { _ in scheduled.cancel() }

                return channel.pipeline.addHandler(handler).flatMap { _ in
                    var buffer = channel.allocator.buffer(capacity: 0)
                    buffer.writeString("")
                    let envelope = AddressedEnvelope(remoteAddress: address, data: buffer)
                    return channel.writeAndFlush(envelope).flatMap { _ in
                        promise.futureResult
                    }
                }.flatMapError { _ in
                    promise.succeed(false)
                    return promise.futureResult
                }
            }.get()

            try? await channel.close().get()

            if hasResponse {
                let service = detectUDPService(port: port)
                return ScanPort(number: port, state: .open, transport: .udp, service: service)
            } else {
                return ScanPort(number: port, state: .filtered, transport: .udp)
            }
        } catch {
            return ScanPort(number: port, state: .closed, transport: .udp)
        }
    }

    private func detectUDPService(port: Int) -> String? {
        let services: [Int: String] = [
            53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp",
            123: "ntp", 137: "netbios-ns", 138: "netbios-dgm",
            161: "snmp", 162: "snmptrap", 514: "syslog",
            520: "rip", 1900: "upnp", 5353: "mdns",
            5355: "llmnr"
        ]
        return services[port]
    }
}

/// Limits concurrent UDP probe tasks to prevent resource exhaustion.
private actor ScanGateUD {
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

/// Handles incoming UDP response packets to determine if a port is open.
/// @unchecked Sendable is required for NIO channel handlers (always run on a single EL).
private final class UDPResponseHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>
    let promise: EventLoopPromise<Bool>

    init(promise: EventLoopPromise<Bool>) {
        self.promise = promise
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        promise.succeed(true)
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        promise.succeed(false)
    }
}
