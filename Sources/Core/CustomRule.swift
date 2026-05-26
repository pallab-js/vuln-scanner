import Foundation

public struct CustomRule: Codable, Identifiable, Sendable, Hashable {
    public var id: String
    public var category: RuleCategory
    public var severity: Double
    public var description: String
    public var recommendation: String
    public var service: String?
    public var port: Int?
    public var pattern: String?
    public var matchOS: Bool
    public var compliance: [String]

    public init(id: String = UUID().uuidString, category: RuleCategory = .outdatedVersion,
                severity: Double = 5.0, description: String = "", recommendation: String = "",
                service: String? = nil, port: Int? = nil, pattern: String? = nil,
                matchOS: Bool = false, compliance: [String] = []) {
        self.id = id
        self.category = category
        self.severity = severity
        self.description = description
        self.recommendation = recommendation
        self.service = service
        self.port = port
        self.pattern = pattern
        self.matchOS = matchOS
        self.compliance = compliance
    }
}

public enum RuleCategory: String, Codable, CaseIterable, Sendable {
    case dangerousPort = "Dangerous Port"
    case weakProtocol = "Weak Protocol"
    case outdatedVersion = "Outdated Version"
    case weakCipher = "Weak Cipher"
    case eolSystem = "EOL System"

    public var systemImage: String {
        switch self {
        case .dangerousPort: return "door.left.hand.open"
        case .weakProtocol: return "shield.slash"
        case .outdatedVersion: return "arrow.triangle.swap"
        case .weakCipher: return "key.slash"
        case .eolSystem: return "desktopcomputer.trianglebadge.exclamationmark"
        }
    }
}

public final class CustomRulesStore: Sendable {
    public static let shared = CustomRulesStore()
    private let logger = Logger(category: .mapping)

    private var storageURL: URL? {
        guard let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            return nil
        }
        let dir = support.appendingPathComponent("com.lanscanner")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("custom_rules.json")
    }

    private init() {}

    public func load() -> [CustomRule] {
        guard let url = storageURL, let data = try? Data(contentsOf: url) else {
            return []
        }
        do {
            let rules = try JSONDecoder().decode([CustomRule].self, from: data)
            logger.info("Loaded \(rules.count) custom rules")
            return rules
        } catch {
            logger.error("Failed to decode custom rules: \(error.localizedDescription)")
            return []
        }
    }

    public func save(_ rules: [CustomRule]) {
        guard let url = storageURL else { return }
        do {
            let data = try JSONEncoder().encode(rules)
            try data.write(to: url, options: .atomic)
            logger.info("Saved \(rules.count) custom rules")
        } catch {
            logger.error("Failed to save custom rules: \(error.localizedDescription)")
        }
    }

    public func delete(id: String) {
        var rules = load()
        rules.removeAll { $0.id == id }
        save(rules)
    }

    public func upsert(_ rule: CustomRule) {
        var rules = load()
        if let idx = rules.firstIndex(where: { $0.id == rule.id }) {
            rules[idx] = rule
        } else {
            rules.append(rule)
        }
        save(rules)
    }
}
