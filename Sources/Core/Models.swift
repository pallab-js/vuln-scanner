import Foundation

// MARK: - Device
public struct Device: Codable, Identifiable, Comparable, Sendable, Hashable {
    public var id: String { ip }
    public let ip: String
    public let mac: String?
    public let host: String?
    public let os: String?
    public let ports: [ScanPort]
    public let vulnerabilities: [Vuln]
    public let firstSeen: Date
    public let lastSeen: Date

    public init(ip: String, mac: String? = nil, host: String? = nil, os: String? = nil,
                ports: [ScanPort] = [], vulnerabilities: [Vuln] = [],
                firstSeen: Date = Date(), lastSeen: Date = Date()) {
        self.ip = ip
        self.mac = mac
        self.host = host
        self.os = os
        self.ports = ports
        self.vulnerabilities = vulnerabilities
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
    }

    public static func < (lhs: Device, rhs: Device) -> Bool {
        lhs.ip < rhs.ip
    }
}

// MARK: - ScanPort
public struct ScanPort: Codable, Identifiable, Comparable, Sendable, Hashable {
    public var id: String { "\(number)/\(transport.rawValue.lowercased())" }
    public let number: Int
    public let state: PortState
    public let transport: TransportProtocol
    public let service: String?
    public let banner: String?

    public init(number: Int, state: PortState, transport: TransportProtocol = .tcp,
                service: String? = nil, banner: String? = nil) {
        self.number = number
        self.state = state
        self.transport = transport
        self.service = service
        self.banner = banner
    }

    public static func < (lhs: ScanPort, rhs: ScanPort) -> Bool {
        lhs.number < rhs.number
    }
}

public enum PortState: String, Codable, Sendable, Comparable {
    case open
    case closed
    case filtered
    case unknown

    public static func < (lhs: PortState, rhs: PortState) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

public enum TransportProtocol: String, Codable, Sendable {
    case tcp = "TCP"
    case udp = "UDP"
}

// MARK: - Service
public struct Service: Codable, Identifiable, Comparable, Sendable, Hashable {
    public var id: String { "\(name)-\(version ?? "unknown")" }
    public let name: String
    public let banner: String?
    public let version: String?
    public let confidence: Double

    public init(name: String, banner: String? = nil, version: String? = nil, confidence: Double = 1.0) {
        self.name = name
        self.banner = banner
        self.version = version
        self.confidence = confidence
    }

    public static func < (lhs: Service, rhs: Service) -> Bool {
        lhs.name < rhs.name
    }
}

// MARK: - Vulnerability
public struct Vuln: Codable, Identifiable, Comparable, Sendable, Hashable {
    public let id: String
    public let severity: Double
    public let description: String
    public let recommendation: String?
    public let cve: String?

    public init(id: String, severity: Double, description: String,
                recommendation: String? = nil, cve: String? = nil) {
        self.id = id
        self.severity = severity
        self.description = description
        self.recommendation = recommendation
        self.cve = cve
    }

    public static func < (lhs: Vuln, rhs: Vuln) -> Bool {
        lhs.severity > rhs.severity
    }
}

public enum SeverityLevel: String, Codable, Sendable, Comparable {
    case critical = "CRITICAL"
    case high = "HIGH"
    case medium = "MEDIUM"
    case low = "LOW"
    case info = "INFO"

    public var range: ClosedRange<Double> {
        switch self {
        case .critical: return 9.0...10.0
        case .high: return 7.0...8.9
        case .medium: return 4.0...6.9
        case .low: return 1.0...3.9
        case .info: return 0.0...0.9
        }
    }

    public static func from(score: Double) -> SeverityLevel {
        switch score {
        case 9.0...: return .critical
        case 7.0...: return .high
        case 4.0...: return .medium
        case 1.0...: return .low
        default: return .info
        }
    }

    public static func < (lhs: SeverityLevel, rhs: SeverityLevel) -> Bool {
        let order: [SeverityLevel] = [.critical, .high, .medium, .low, .info]
        guard let l = order.firstIndex(of: lhs), let r = order.firstIndex(of: rhs) else {
            return false
        }
        return l < r
    }
}

// MARK: - Scan Configuration
public struct ScanConfig: Codable, Sendable {
    public var portRange: ClosedRange<Int>
    public var timeout: TimeInterval
    public var maxConcurrency: Int
    public var excludeIPs: [String]
    public var serviceDetection: Bool
    public var osDetection: Bool

    public static let `default` = ScanConfig(
        portRange: 1...1024,
        timeout: 2.0,
        maxConcurrency: 32,
        excludeIPs: [],
        serviceDetection: true,
        osDetection: true
    )

    public init(portRange: ClosedRange<Int>, timeout: TimeInterval, maxConcurrency: Int,
                excludeIPs: [String], serviceDetection: Bool, osDetection: Bool) {
        self.portRange = portRange
        self.timeout = timeout
        self.maxConcurrency = min(maxConcurrency, 64)
        self.excludeIPs = excludeIPs
        self.serviceDetection = serviceDetection
        self.osDetection = osDetection
    }
}

// MARK: - Scan Result
public struct ScanResult: Codable, Sendable {
    public let devices: [Device]
    public let scanDuration: TimeInterval
    public let totalPortsScanned: Int
    public let timestamp: Date

    public init(devices: [Device], scanDuration: TimeInterval, totalPortsScanned: Int, timestamp: Date = Date()) {
        self.devices = devices
        self.scanDuration = scanDuration
        self.totalPortsScanned = totalPortsScanned
        self.timestamp = timestamp
    }
}
