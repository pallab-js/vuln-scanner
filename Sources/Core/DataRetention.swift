import Foundation

public struct RetentionPolicy: Codable, Sendable {
    public var maxScans: Int
    public var maxAgeDays: Int
    public var autoPurgeOnLaunch: Bool

    public static let `default` = RetentionPolicy(maxScans: 200, maxAgeDays: 90, autoPurgeOnLaunch: true)
}

public final class RetentionManager: @unchecked Sendable {
    public static let shared = RetentionManager()
    public var policy: RetentionPolicy {
        get { loadPolicy() }
        set { savePolicy(newValue) }
    }

    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    private var policyURL: URL? {
        guard let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else { return nil }
        let appDir = dir.appendingPathComponent("com.lanscanner")
        try? FileManager.default.createDirectory(at: appDir, withIntermediateDirectories: true)
        return appDir.appendingPathComponent("retention.json")
    }

    public func enforce(on store: ScanStore) {
        let p = policy
        var purged = false

        if p.maxAgeDays > 0 {
            let cutoff = Date().addingTimeInterval(-Double(p.maxAgeDays) * 86400)
            if store.deleteOlderThan(cutoff) > 0 { purged = true }
        }

        if p.maxScans > 0 {
            if store.trim(toMax: p.maxScans) > 0 { purged = true }
        }

        if purged {
            AuditLogger.shared.log(action: .retentionPurged, detail: "Retention policy enforced: max \(p.maxScans) scans, \(p.maxAgeDays) days", category: .dataManagement)
        }
    }

    private func loadPolicy() -> RetentionPolicy {
        guard let url = policyURL, let data = try? Data(contentsOf: url),
              let p = try? decoder.decode(RetentionPolicy.self, from: data) else { return .default }
        return p
    }

    private func savePolicy(_ p: RetentionPolicy) {
        guard let url = policyURL, let data = try? encoder.encode(p) else { return }
        try? data.write(to: url, options: .atomic)
    }
}
