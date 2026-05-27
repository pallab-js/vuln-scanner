import Foundation
import os

public struct ConfigProfile: Codable, Identifiable, Sendable {
    public var id: String { name }
    public let name: String
    public let config: ScanConfig
    public let createdAt: Date
    public let description: String

    public init(name: String, config: ScanConfig, description: String = "") {
        self.name = name
        self.config = config
        self.createdAt = Date()
        self.description = description
    }
}

public final class ProfileManager: @unchecked Sendable {
    public static let shared = ProfileManager()

    private var profiles: [ConfigProfile] = []
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()
    private let lock = OSAllocatedUnfairLock()

    private var storeURL: URL? {
        guard let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else { return nil }
        let appDir = dir.appendingPathComponent("com.lanscanner")
        try? FileManager.default.createDirectory(at: appDir, withIntermediateDirectories: true)
        return appDir.appendingPathComponent("profiles.json")
    }

    private init() { load() }

    public func all() -> [ConfigProfile] {
        lock.lock(); defer { lock.unlock() }
        return profiles
    }

    public func save(name: String, config: ScanConfig, description: String = "") {
        let profile = ConfigProfile(name: name, config: config, description: description)
        lock.lock()
        profiles.removeAll { $0.name == name }
        profiles.append(profile)
        lock.unlock()
        persist()
        AuditLogger.shared.log(action: .profileSaved, detail: "Saved profile '\(name)'", category: .configuration)
    }

    public func apply(name: String) -> ScanConfig? {
        lock.lock()
        guard let profile = profiles.first(where: { $0.name == name }) else {
            lock.unlock()
            return nil
        }
        lock.unlock()
        AuditLogger.shared.log(action: .profileApplied, detail: "Applied profile '\(name)'", category: .configuration)
        return profile.config
    }

    public func delete(name: String) {
        lock.lock()
        profiles.removeAll { $0.name == name }
        lock.unlock()
        persist()
    }

    private func persist() {
        guard let url = storeURL, let data = try? encoder.encode(profiles) else { return }
        try? data.write(to: url, options: .atomic)
    }

    private func load() {
        guard let url = storeURL, let data = try? Data(contentsOf: url),
              let loaded = try? decoder.decode([ConfigProfile].self, from: data) else { return }
        lock.lock()
        profiles = loaded
        lock.unlock()
    }
}
