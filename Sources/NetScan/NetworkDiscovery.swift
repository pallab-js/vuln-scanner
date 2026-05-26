import Foundation
import SystemConfiguration
import Core

public enum NetworkDiscoveryError: Error, Sendable, LocalizedError {
    case noActiveInterface
    case subnetResolutionFailed
    case timeout

    public var errorDescription: String? {
        switch self {
        case .noActiveInterface: return "No active network interface found"
        case .subnetResolutionFailed: return "Failed to resolve subnet"
        case .timeout: return "Discovery timed out"
        }
    }
}

public actor ConcurrencyGate {
    private let maxConcurrency: Int
    private var running: Int = 0

    public init(maxConcurrency: Int) {
        self.maxConcurrency = maxConcurrency
    }

    public func waitIfNeeded() async {
        while running >= maxConcurrency {
            try? await Task.sleep(for: .milliseconds(50))
        }
        running += 1
    }

    public func signal() {
        running -= 1
    }
}

public struct NetworkDiscovery: Sendable {
    private let logger: Logger
    private let gate: ConcurrencyGate

    public init(maxConcurrency: Int = 32) {
        self.logger = Logger(category: .discovery)
        self.gate = ConcurrencyGate(maxConcurrency: min(maxConcurrency, 64))
    }

    public func scanSubnet(timeout: TimeInterval = 10.0) async throws -> [Device] {
        logger.notice("Starting LAN discovery (timeout: \(timeout)s)")

        let subnet = try await resolveLocalSubnet()
        logger.info("Scanning subnet: \(subnet.network)/\(subnet.prefix)")

        let hosts = try await resolveActiveHosts(on: subnet, timeout: timeout)

        let devices = hosts.map { host in
            Device(ip: host.ip, mac: host.mac, host: host.hostname)
        }

        logger.notice("Discovery complete: \(devices.count) devices found")
        return devices
    }

    private func resolveLocalSubnet() async throws -> Subnet {
        let interface = try await resolvePrimaryInterface()
        guard let subnet = interface.subnet else {
            logger.error("No subnet found on interface \(interface.name)")
            throw NetworkDiscoveryError.subnetResolutionFailed
        }
        return subnet
    }

    private func resolvePrimaryInterface() async throws -> NetworkInterface {
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let firstAddr = ifaddr else {
            throw NetworkDiscoveryError.noActiveInterface
        }
        defer { freeifaddrs(ifaddr) }

        var ptr = firstAddr
        while true {
            let info = ptr.pointee
            let name = String(cString: info.ifa_name)
            let addrFamily = info.ifa_addr.pointee.sa_family

            if addrFamily == sa_family_t(AF_INET),
               name.hasPrefix("en") || name == "en0" {
                let flags = Int32(info.ifa_flags)
                if (flags & IFF_UP) != 0 && (flags & IFF_RUNNING) != 0 {
                    var addr = info.ifa_addr.pointee
                    var netmask = info.ifa_netmask.pointee

                    let addrData = withUnsafePointer(to: &addr) {
                        $0.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
                    }
                    let maskData = withUnsafePointer(to: &netmask) {
                        $0.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
                    }

                    let ip = String(cString: inet_ntoa(addrData.sin_addr))
                    let mask = String(cString: inet_ntoa(maskData.sin_addr))

                    let interface = NetworkInterface(name: name, ip: ip, netmask: mask)
                    logger.debug("Primary interface: \(name) (\(ip)/\(mask))")
                    return interface
                }
            }

            if let next = info.ifa_next {
                ptr = next
            } else {
                break
            }
        }
        throw NetworkDiscoveryError.noActiveInterface
    }
}

// MARK: - Supporting Types
public struct NetworkInterface: Sendable {
    public let name: String
    public let ip: String
    public let netmask: String

    public var subnet: Subnet? {
        guard let ipAddr = ipv4ToUInt32(ip),
              let maskAddr = ipv4ToUInt32(netmask) else {
            return nil
        }
        let networkAddr = ipAddr & maskAddr
        let broadcastAddr = networkAddr | ~maskAddr
        let prefix = maskAddr.nonzeroBitCount

        return Subnet(
            network: uint32ToIPv4(networkAddr),
            broadcast: uint32ToIPv4(broadcastAddr),
            netmask: netmask,
            prefix: prefix,
            networkUInt32: networkAddr,
            broadcastUInt32: broadcastAddr,
            maskUInt32: maskAddr
        )
    }
}

public struct Subnet: Sendable {
    public let network: String
    public let broadcast: String
    public let netmask: String
    public let prefix: Int
    public let networkUInt32: UInt32
    public let broadcastUInt32: UInt32
    public let maskUInt32: UInt32

    public var usableHostCount: Int {
        let count = Int(broadcastUInt32 - networkUInt32 - 1)
        return max(0, count)
    }
}

public struct ActiveHost: Sendable {
    public let ip: String
    public let mac: String?
    public let hostname: String?
}

// MARK: - Host Discovery
extension NetworkDiscovery {
    private func resolveActiveHosts(on subnet: Subnet, timeout: TimeInterval) async throws -> [ActiveHost] {
        try await withThrowingTaskGroup(of: ActiveHost?.self) { group in
            var hosts: [ActiveHost] = []
            let startTime = Date()
            var totalProbed = 0

            for ipU32 in (subnet.networkUInt32 + 1)..<subnet.broadcastUInt32 {
                try Task.checkCancellation()

                let elapsed = Date().timeIntervalSince(startTime)
                guard elapsed < timeout else {
                    logger.notice("Discovery timed out, probed \(totalProbed) IPs, found \(hosts.count) hosts")
                    break
                }

                await gate.waitIfNeeded()
                totalProbed += 1

                let ip = uint32ToIPv4(ipU32)
                let gate = self.gate
                group.addTask {
                    let result = await Self.probeHostStatic(ip: ip)
                    await gate.signal()
                    return result
                }
            }

            for try await result in group {
                if let host = result {
                    hosts.append(host)
                }
            }

            return hosts.sorted { $0.ip < $1.ip }
        }
    }

    private static func probeHostStatic(ip: String) async -> ActiveHost? {
        let reachable = await Self.checkReachabilityStatic(ip: ip)
        guard reachable else { return nil }

        async let hostname = Self.resolveHostnameStatic(ip: ip)
        async let mac = Self.resolveMACStatic(ip: ip)

        let (resolvedHostname, resolvedMAC) = await (hostname, mac)
        Logger.discovery.debug("Found host: \(ip)\(resolvedMAC.map { " (\($0))" } ?? "")")
        return ActiveHost(ip: ip, mac: resolvedMAC, hostname: resolvedHostname)
    }

    private static func checkReachabilityStatic(ip: String) async -> Bool {
        await withCheckedContinuation { continuation in
            guard let cString = (ip as NSString).utf8String,
                  let reachability = SCNetworkReachabilityCreateWithName(nil, cString) else {
                continuation.resume(returning: false)
                return
            }
            var flags = SCNetworkReachabilityFlags()
            SCNetworkReachabilityGetFlags(reachability, &flags)
            continuation.resume(returning: flags.contains(.reachable))
        }
    }

    private static func resolveHostnameStatic(ip: String) async -> String? {
        await withCheckedContinuation { continuation in
            let host = CFHostCreateWithName(nil, ip as CFString).takeRetainedValue()
            var resolved = DarwinBoolean(false)
            CFHostStartInfoResolution(host, .names, nil)
            if let names = CFHostGetNames(host, &resolved)?.takeUnretainedValue() as? [String],
               let name = names.first {
                continuation.resume(returning: name)
            } else {
                continuation.resume(returning: nil)
            }
        }
    }

    private static func resolveMACStatic(ip: String) async -> String? {
        let task = Process()
        task.launchPath = "/usr/sbin/arp"
        task.arguments = ["-an"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe

        do {
            try task.run()
            task.waitUntilExit()
            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            guard let output = String(data: outputData, encoding: .utf8) else { return nil }

            for line in output.components(separatedBy: .newlines) {
                let parts = line.components(separatedBy: .whitespaces).filter { !$0.isEmpty }
                guard parts.count >= 4 else { continue }
                let ipPart = parts[0].trimmingCharacters(in: CharacterSet(charactersIn: "()"))
                guard ipPart == ip else { continue }
                let mac = parts[3]
                guard mac != "(incomplete)" else { continue }
                return mac
            }
        } catch {
            return nil
        }
        return nil
    }

}

// MARK: - IP Utils
public func ipv4ToUInt32(_ ip: String) -> UInt32? {
    var addr = in_addr()
    guard inet_pton(AF_INET, ip, &addr) == 1 else { return nil }
    return UInt32(bigEndian: addr.s_addr)
}

public func uint32ToIPv4(_ value: UInt32) -> String {
    let addr = in_addr(s_addr: value.bigEndian)
    return String(cString: inet_ntoa(addr))
}
