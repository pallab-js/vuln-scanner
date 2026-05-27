import Foundation

public struct ExportDevice: Codable, Sendable {
    public let ip: String
    public let mac: String?
    public let host: String?
    public let os: String?
    public let riskScore: Double
    public let openPorts: [ExportPort]
    public let vulnerabilities: [ExportVuln]

    public init(ip: String, mac: String?, host: String?, os: String?, riskScore: Double, openPorts: [ExportPort], vulnerabilities: [ExportVuln]) {
        self.ip = ip
        self.mac = mac
        self.host = host
        self.os = os
        self.riskScore = riskScore
        self.openPorts = openPorts
        self.vulnerabilities = vulnerabilities
    }
}

public struct ExportPort: Codable, Sendable {
    public let port: Int
    public let service: String?
    public let banner: String?

    public init(port: Int, service: String?, banner: String?) {
        self.port = port
        self.service = service
        self.banner = banner
    }
}

public struct ExportVuln: Codable, Sendable {
    public let id: String
    public let severity: Double
    public let description: String
    public let recommendation: String?
    public let cve: String?

    public init(id: String, severity: Double, description: String, recommendation: String?, cve: String?) {
        self.id = id
        self.severity = severity
        self.description = description
        self.recommendation = recommendation
        self.cve = cve
    }
}

public func mapToExportDevice(_ d: Device) -> ExportDevice {
    ExportDevice(
        ip: d.ip,
        mac: d.mac,
        host: d.host,
        os: d.os,
        riskScore: d.riskScore,
        openPorts: d.ports.filter { $0.state == .open }.map { ExportPort(port: $0.number, service: $0.service, banner: $0.banner) },
        vulnerabilities: d.vulnerabilities.map { ExportVuln(id: $0.id, severity: $0.severity, description: $0.description, recommendation: $0.recommendation, cve: $0.cve) }
    )
}
