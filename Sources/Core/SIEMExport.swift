import Foundation

public enum SIEMFormat: String, Codable, Sendable, CaseIterable {
    case cef = "CEF"
    case leef = "LEEF"
    case syslog = "Syslog"
    case rawJSON = "Raw JSON"
}

public struct SIEMConfig: Codable, Sendable {
    public var enabled: Bool
    public var format: SIEMFormat
    public var syslogHost: String
    public var syslogPort: Int
    public var facility: Int

    public static let `default` = SIEMConfig(enabled: false, format: .cef, syslogHost: "", syslogPort: 514, facility: 3)
}

public final class SIEMExporter: @unchecked Sendable {
    public static let shared = SIEMExporter()

    public func export(devices: [Device], format: SIEMFormat) -> String {
        switch format {
        case .cef: return cef(devices: devices)
        case .leef: return leef(devices: devices)
        case .syslog: return syslog(devices: devices)
        case .rawJSON: return rawJSON(devices: devices)
        }
    }

    private func cef(devices: [Device]) -> String {
        let vendor = "LANScanner"
        let product = "VulnerabilityScanner"
        let version = "1.0"
        return devices.flatMap { device -> [String] in
            device.vulnerabilities.map { vuln in
                let severity = Int(vuln.severity)
                let sig = vuln.cve ?? vuln.id
                return "CEF:0|\(vendor)|\(product)|\(version)|\(sig)|\(vuln.description.prefix(200))|\(severity)|" +
                    "src=\(device.ip) dst=\(device.ip) msg=\(vuln.description.prefix(200))"
            }
        }.joined(separator: "\n")
    }

    private func leef(devices: [Device]) -> String {
        let header = "LEEF:2.0|LANScanner|VulnerabilityScanner|1.0|VulnEvent|"
        return devices.flatMap { device -> [String] in
            device.vulnerabilities.map { vuln in
                let fields = [
                    "sev=\(Int(vuln.severity))",
                    "src=\(device.ip)",
                    "sig=\(vuln.cve ?? vuln.id)",
                    "desc=\(vuln.description.prefix(200))",
                    "os=\(device.os ?? "unknown")"
                ]
                return header + fields.joined(separator: "\t")
            }
        }.joined(separator: "\n")
    }

    private func syslog(devices: [Device]) -> String {
        let timestamp = ISO8601DateFormatter()
        return devices.flatMap { device -> [String] in
            device.vulnerabilities.map { vuln in
                "\(timestamp.string(from: Date())) LANScanner Vuln: sev=\(Int(vuln.severity)) src=\(device.ip) sig=\(vuln.cve ?? vuln.id) desc='\(vuln.description.prefix(200))'"
            }
        }.joined(separator: "\n")
    }

    private func rawJSON(devices: [Device]) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = devices.map { d in SIEMDevice(ip: d.ip, mac: d.mac, host: d.host, os: d.os, riskScore: d.riskScore, vulnerabilities: d.vulnerabilities.map { SIEMVuln(id: $0.id, severity: $0.severity, description: $0.description, cve: $0.cve) }) }
        guard let json = try? encoder.encode(data) else { return "[]" }
        return String(data: json, encoding: .utf8) ?? "[]"
    }
}

private struct SIEMDevice: Codable { let ip: String; let mac: String?; let host: String?; let os: String?; let riskScore: Double; let vulnerabilities: [SIEMVuln] }
private struct SIEMVuln: Codable { let id: String; let severity: Double; let description: String; let cve: String? }
