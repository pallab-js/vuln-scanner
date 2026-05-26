import Foundation
import Core

public struct VulnMapper: Sendable {
    private let rules: VulnRules
    private let logger = Logger(category: .mapping)

    public init() {
        self.rules = RuleLoader.load()
        logger.info("VulnMapper initialized with \(rules.allRules.count) rules")
    }

    public func map(device: Device) -> [Vuln] {
        var vulns: [Vuln] = []

        for port in device.ports {
            vulns.append(contentsOf: evaluatePort(port))
            if let serviceName = port.service {
                vulns.append(contentsOf: evaluateService(name: serviceName, banner: port.banner))
            }
        }

        if let os = device.os {
            vulns.append(contentsOf: evaluateOS(os))
        }

        return vulns.uniqued().sorted()
    }

    public func map(services: [Service]) -> [Vuln] {
        var vulns: [Vuln] = []
        for service in services {
            vulns.append(contentsOf: evaluateService(name: service.name, banner: service.banner))
        }
        return vulns.uniqued().sorted()
    }

    private func makeVuln(from rule: VulnRule) -> Vuln {
        let compliance: [ComplianceFramework] = (rule.compliance ?? []).compactMap { ComplianceFramework(rawValue: $0) }
        return Vuln(id: rule.id, severity: rule.severity, description: rule.description,
                    recommendation: rule.recommendation, compliance: compliance)
    }

    private func evaluatePort(_ port: ScanPort) -> [Vuln] {
        guard port.state == .open else { return [] }
        var vulns: [Vuln] = []

        for rule in rules.dangerousPorts where rule.port == port.number {
            vulns.append(makeVuln(from: rule))
        }
        for rule in rules.weakProtocols {
            if let service = rule.service, port.service?.lowercased() == service.lowercased() {
                vulns.append(makeVuln(from: rule))
            }
        }
        return vulns
    }

    private func evaluateService(name: String, banner: String?) -> [Vuln] {
        var vulns: [Vuln] = []

        for rule in rules.weakProtocols {
            if let service = rule.service, name.lowercased() == service.lowercased() {
                vulns.append(makeVuln(from: rule))
            }
        }

        if let banner = banner {
            for rule in rules.outdatedVersions {
                if let service = rule.service, service != name.lowercased() { continue }
                if let pattern = rule.pattern {
                    do {
                        let regex = try Regex(pattern)
                        if banner.contains(regex) { vulns.append(makeVuln(from: rule)) }
                    } catch {
                        logger.error("Invalid regex pattern: \(pattern) - \(error.localizedDescription)")
                    }
                }
            }

            for rule in rules.weakCiphers {
                if let service = rule.service, name.lowercased().contains(service) {
                    if let pattern = rule.pattern {
                        do {
                            let regex = try Regex(pattern)
                            if banner.contains(regex) { vulns.append(makeVuln(from: rule)) }
                        } catch {
                            logger.error("Invalid regex pattern: \(pattern)")
                        }
                    }
                }
            }
        }
        return vulns
    }

    private func evaluateOS(_ os: String) -> [Vuln] {
        var vulns: [Vuln] = []

        for rule in rules.eolSystems {
            if let pattern = rule.pattern {
                do {
                    let regex = try Regex(pattern)
                    if os.contains(regex) { vulns.append(makeVuln(from: rule)) }
                } catch {
                    logger.error("Invalid OS pattern: \(pattern)")
                }
            }
        }
        return vulns
    }
}

// MARK: - Helpers
extension Array where Element == Vuln {
    func uniqued() -> [Vuln] {
        var seen = Set<String>()
        return filter { seen.insert($0.id).inserted }
    }
}
