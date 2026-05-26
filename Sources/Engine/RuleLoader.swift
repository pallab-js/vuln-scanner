import Foundation
import Core

public struct VulnRule: Codable, Sendable {
    public let id: String
    public let severity: Double
    public let description: String
    public let recommendation: String?
    public let service: String?
    public let pattern: String?
    public let port: Int?
    public let compliance: [String]?
}

public struct VulnRules: Codable, Sendable {
    public let version: Int
    public let weakProtocols: [VulnRule]
    public let outdatedVersions: [VulnRule]
    public let weakCiphers: [VulnRule]
    public let eolSystems: [VulnRule]
    public let dangerousPorts: [VulnRule]
}

public enum RuleLoader {
    public static func load() -> VulnRules {
        guard let url = Bundle.module.url(forResource: "rules", withExtension: "json") else {
            Logger.mapping.error("Failed to find rules.json in bundle")
            return emptyRules()
        }
        do {
            let data = try Data(contentsOf: url)
            let decoder = JSONDecoder()
            let rules = try decoder.decode(VulnRules.self, from: data)
            Logger.mapping.info("Loaded \(rules.allRules.count) vuln rules (v\(rules.version))")
            return rules
        } catch {
            Logger.mapping.error("Failed to load rules.json: \(error.localizedDescription)")
            return emptyRules()
        }
    }

    private static func emptyRules() -> VulnRules {
        VulnRules(
            version: 0,
            weakProtocols: [],
            outdatedVersions: [],
            weakCiphers: [],
            eolSystems: [],
            dangerousPorts: []
        )
    }
}

public extension VulnRules {
    var allRules: [VulnRule] {
        weakProtocols + outdatedVersions + weakCiphers + eolSystems + dangerousPorts
    }
}
