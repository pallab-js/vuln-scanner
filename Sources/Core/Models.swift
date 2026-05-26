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

    public var riskScore: Double {
        guard !ports.isEmpty || !vulnerabilities.isEmpty else { return 0 }
        let vulnScore = vulnerabilities.reduce(0.0) { $0 + $1.severity }
        let avgVuln = vulnerabilities.isEmpty ? 0 : vulnScore / Double(vulnerabilities.count)
        let portWeight = min(Double(ports.filter { $0.state == .open }.count) * 0.5, 5)
        let highVulnBonus = vulnerabilities.contains(where: { $0.severity >= 7 }) ? 1.0 : 0
        return min(avgVuln + portWeight + highVulnBonus, 10)
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
    public let compliance: [ComplianceFramework]

    public init(id: String, severity: Double, description: String,
                recommendation: String? = nil, cve: String? = nil,
                compliance: [ComplianceFramework] = []) {
        self.id = id
        self.severity = severity
        self.description = description
        self.recommendation = recommendation
        self.cve = cve
        self.compliance = compliance
    }

    public var complianceIDs: [String] { compliance.map(\.rawValue) }

    public static func < (lhs: Vuln, rhs: Vuln) -> Bool {
        lhs.severity > rhs.severity
    }
}

public enum ComplianceFramework: String, Codable, CaseIterable, Sendable, Hashable {
    case pciDSS = "PCI-DSS"
    case hipaa = "HIPAA"
    case gdpr = "GDPR"
    case soc2 = "SOC2"
    case nist = "NIST"

    public var displayName: String { rawValue }
}

public enum SeverityLevel: String, CaseIterable, Codable, Sendable, Comparable {
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

// MARK: - Scan Summary (for history list)
public struct ScanSummary: Codable, Identifiable, Sendable {
    public var id: String { scanID }
    public let scanID: String
    public let timestamp: Date
    public let duration: TimeInterval
    public let deviceCount: Int
    public let totalOpenPorts: Int
    public let totalVulnerabilities: Int
    public let riskScore: Double
    public let config: ScanConfig

    public init(scanID: String = UUID().uuidString, timestamp: Date = Date(), duration: TimeInterval,
                deviceCount: Int, totalOpenPorts: Int, totalVulnerabilities: Int,
                riskScore: Double, config: ScanConfig) {
        self.scanID = scanID
        self.timestamp = timestamp
        self.duration = duration
        self.deviceCount = deviceCount
        self.totalOpenPorts = totalOpenPorts
        self.totalVulnerabilities = totalVulnerabilities
        self.riskScore = riskScore
        self.config = config
    }
}

// MARK: - Trend Data Point
public struct TrendPoint: Codable, Identifiable, Sendable, Hashable {
    public var id: String { "\(date.timeIntervalSince1970)-\(metric)" }
    public let date: Date
    public let metric: String
    public let value: Double

    public init(date: Date, metric: String, value: Double) {
        self.date = date
        self.metric = metric
        self.value = value
    }
}

// MARK: - Trend Data
public struct TrendData: Codable, Sendable {
    public let totalScans: Int
    public let vulnsOverTime: [TrendPoint]
    public let devicesOverTime: [TrendPoint]
    public let riskOverTime: [TrendPoint]
    public let topCVE: [CVECount]

    public init(totalScans: Int, vulnsOverTime: [TrendPoint], devicesOverTime: [TrendPoint],
                riskOverTime: [TrendPoint], topCVE: [CVECount]) {
        self.totalScans = totalScans
        self.vulnsOverTime = vulnsOverTime
        self.devicesOverTime = devicesOverTime
        self.riskOverTime = riskOverTime
        self.topCVE = topCVE
    }
}

public struct CVECount: Codable, Identifiable, Sendable, Hashable {
    public var id: String { cve }
    public let cve: String
    public let count: Int

    public init(cve: String, count: Int) {
        self.cve = cve
        self.count = count
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
    public var scanUDP: Bool
    public var udpPortRange: ClosedRange<Int>
    public var subnetCIDR: String?
    public var webhookEnabled: Bool
    public var webhookURL: String
    public var scheduleEnabled: Bool
    public var scheduleIntervalHours: Double
    public var apiEnabled: Bool
    public var apiPort: Int
    public var autoUpdateRules: Bool
    public var rulesURL: String

    public static let `default` = ScanConfig(
        portRange: 1...1024,
        timeout: 2.0,
        maxConcurrency: 32,
        excludeIPs: [],
        serviceDetection: true,
        osDetection: true,
        scanUDP: false,
        udpPortRange: 1...1024,
        subnetCIDR: nil,
        webhookEnabled: false,
        webhookURL: "",
        scheduleEnabled: false,
        scheduleIntervalHours: 24,
        apiEnabled: false,
        apiPort: 8080,
        autoUpdateRules: false,
        rulesURL: ""
    )

    public init(portRange: ClosedRange<Int>, timeout: TimeInterval, maxConcurrency: Int,
                excludeIPs: [String], serviceDetection: Bool, osDetection: Bool,
                scanUDP: Bool = false, udpPortRange: ClosedRange<Int> = 1...1024,
                subnetCIDR: String? = nil, webhookEnabled: Bool = false, webhookURL: String = "",
                scheduleEnabled: Bool = false, scheduleIntervalHours: Double = 24,
                apiEnabled: Bool = false, apiPort: Int = 8080,
                autoUpdateRules: Bool = false, rulesURL: String = "") {
        self.portRange = portRange
        self.timeout = timeout
        self.maxConcurrency = min(maxConcurrency, 64)
        self.excludeIPs = excludeIPs
        self.serviceDetection = serviceDetection
        self.osDetection = osDetection
        self.scanUDP = scanUDP
        self.udpPortRange = udpPortRange
        self.subnetCIDR = subnetCIDR
        self.webhookEnabled = webhookEnabled
        self.webhookURL = webhookURL
        self.scheduleEnabled = scheduleEnabled
        self.scheduleIntervalHours = max(1, min(scheduleIntervalHours, 168))
        self.apiEnabled = apiEnabled
        self.apiPort = max(1024, min(apiPort, 65535))
        self.autoUpdateRules = autoUpdateRules
        self.rulesURL = rulesURL
    }
}

// MARK: - Network Error
public enum NetworkError: Error, Sendable, LocalizedError, Equatable {
    case connectionTimeout(String)
    case connectionRefused(String)
    case dnsResolutionFailed(String)
    case noRouteToHost(String)
    case networkUnreachable
    case permissionDenied
    case scanCancelled
    case invalidIP(String)
    case invalidPort(Int)
    case unknown(String)

    public static func == (lhs: NetworkError, rhs: NetworkError) -> Bool {
        switch (lhs, rhs) {
        case (.connectionTimeout, .connectionTimeout),
            (.connectionRefused, .connectionRefused),
            (.dnsResolutionFailed, .dnsResolutionFailed),
            (.noRouteToHost, .noRouteToHost),
            (.networkUnreachable, .networkUnreachable),
            (.permissionDenied, .permissionDenied),
            (.scanCancelled, .scanCancelled),
            (.invalidIP, .invalidIP),
            (.invalidPort, .invalidPort),
            (.unknown, .unknown):
            return true
        default:
            return false
        }
    }

    public var errorDescription: String? {
        switch self {
        case .connectionTimeout(let target): return "Connection timed out: \(target)"
        case .connectionRefused(let target): return "Connection refused: \(target)"
        case .dnsResolutionFailed(let host): return "DNS resolution failed: \(host)"
        case .noRouteToHost(let target): return "No route to host: \(target)"
        case .networkUnreachable: return "Network is unreachable"
        case .permissionDenied: return "Permission denied"
        case .scanCancelled: return "Scan was cancelled"
        case .invalidIP(let ip): return "Invalid IP address: \(ip)"
        case .invalidPort(let p): return "Invalid port number: \(p)"
        case .unknown(let msg): return "Unknown error: \(msg)"
        }
    }

    public static func from(_ error: Error) -> NetworkError {
        let desc = error.localizedDescription.lowercased()
        switch error {
        case is CancellationError:
            return .scanCancelled
        case let posixError as POSIXError:
            switch posixError.code {
            case .ECONNREFUSED: return .connectionRefused(desc)
            case .ETIMEDOUT: return .connectionTimeout(desc)
            case .EHOSTUNREACH: return .noRouteToHost(desc)
            case .ENETUNREACH: return .networkUnreachable
            case .EACCES, .EPERM: return .permissionDenied
            default: return .unknown(desc)
            }
        default:
            if desc.contains("timed out") || desc.contains("timeout") {
                return .connectionTimeout(desc)
            }
            if desc.contains("refused") || desc.contains("reset") {
                return .connectionRefused(desc)
            }
            if desc.contains("unreachable") {
                return .networkUnreachable
            }
            if desc.contains("permission") || desc.contains("denied") {
                return .permissionDenied
            }
            if desc.contains("cancelled") {
                return .scanCancelled
            }
            return .unknown(desc)
        }
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
