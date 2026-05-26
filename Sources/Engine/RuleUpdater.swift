import Foundation
import CryptoKit
import Core

public enum RuleUpdateError: Error, LocalizedError, Sendable {
    case invalidURL
    case downloadFailed(String)
    case hashMismatch
    case invalidRules

    public var errorDescription: String? {
        switch self {
        case .invalidURL: return "Invalid rules URL"
        case .downloadFailed(let msg): return "Download failed: \(msg)"
        case .hashMismatch: return "Downloaded rules hash does not match expected value"
        case .invalidRules: return "Downloaded rules file is invalid"
        }
    }
}

public enum RuleUpdater {
    private static let logger = Logger(category: .mapping)
    private static let decoder = JSONDecoder()

    private static var cacheURL: URL? {
        guard let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            return nil
        }
        let dir = support.appendingPathComponent("com.lanscanner")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("cached_rules.json")
    }

    private static var metaURL: URL? {
        guard let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            return nil
        }
        let dir = support.appendingPathComponent("com.lanscanner")
        return dir.appendingPathComponent("cached_rules_meta.json")
    }

    public static var cachedVersion: Int? {
        guard let url = metaURL, let data = try? Data(contentsOf: url),
              let meta = try? decoder.decode(RuleMeta.self, from: data) else {
            return nil
        }
        return meta.version
    }

    public static var lastUpdateDate: Date? {
        guard let url = metaURL, let data = try? Data(contentsOf: url),
              let meta = try? decoder.decode(RuleMeta.self, from: data) else {
            return nil
        }
        return meta.date
    }

    public static func update(from urlString: String, expectedHash: String? = nil) async throws -> VulnRules {
        guard let url = URL(string: urlString) else {
            throw RuleUpdateError.invalidURL
        }

        logger.notice("Fetching rules from \(urlString)")
        let (data, response) = try await URLSession.shared.data(from: url)

        guard let httpResponse = response as? HTTPURLResponse,
              (200...299).contains(httpResponse.statusCode) else {
            throw RuleUpdateError.downloadFailed("HTTP \((response as? HTTPURLResponse)?.statusCode ?? -1)")
        }

        if let expectedHash {
            let actualHash = sha256(data)
            guard actualHash == expectedHash.lowercased() else {
                logger.error("Hash mismatch: expected \(expectedHash), got \(actualHash)")
                throw RuleUpdateError.hashMismatch
            }
        }

        let rules = try decoder.decode(VulnRules.self, from: data)
        guard !rules.allRules.isEmpty else {
            throw RuleUpdateError.invalidRules
        }

        cache(data: data, rules: rules)
        logger.notice("Rules updated to v\(rules.version) (\(rules.allRules.count) signatures)")
        return rules
    }

    public static func loadCached() -> VulnRules? {
        guard let url = cacheURL, let data = try? Data(contentsOf: url) else { return nil }
        guard let rules = try? decoder.decode(VulnRules.self, from: data) else { return nil }
        logger.info("Loaded \(rules.allRules.count) cached rules (v\(rules.version))")
        return rules
    }

    public static func clearCache() {
        guard let url = cacheURL else { return }
        try? FileManager.default.removeItem(at: url)
        if let meta = metaURL { try? FileManager.default.removeItem(at: meta) }
        logger.notice("Rules cache cleared")
    }

    public static func isCacheStale(maxAgeDays: Int = 30) -> Bool {
        guard let date = lastUpdateDate else { return true }
        return -date.timeIntervalSinceNow > Double(maxAgeDays * 86400)
    }

    // MARK: - Private
    private static func cache(data: Data, rules: VulnRules) {
        guard let url = cacheURL else { return }
        try? data.write(to: url, options: .atomic)
        let meta = RuleMeta(version: rules.version, date: Date(), ruleCount: rules.allRules.count)
        if let metaURL, let metaData = try? JSONEncoder().encode(meta) {
            try? metaData.write(to: metaURL, options: .atomic)
        }
    }

    private static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

private struct RuleMeta: Codable {
    let version: Int
    let date: Date
    let ruleCount: Int
}
