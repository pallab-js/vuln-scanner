import Foundation
import os

public enum UserRole: String, Codable, Sendable, CaseIterable {
    case admin = "Admin"
    case operator_ = "Operator"
    case viewer = "Viewer"
    case auditor = "Auditor"

    public var canScan: Bool { self != .viewer && self != .auditor }
    public var canConfigure: Bool { self == .admin || self == .operator_ }
    public var canManageUsers: Bool { self == .admin }
    public var canExport: Bool { self != .viewer }
    public var canDeleteHistory: Bool { self == .admin || self == .operator_ }
}

public struct AuditEvent: Codable, Identifiable, Sendable {
    public var id: String { eventID }
    public let eventID: String
    public let timestamp: Date
    public let user: String
    public let role: UserRole
    public let action: AuditAction
    public let detail: String
    public let category: AuditCategory

    public init(user: String, role: UserRole, action: AuditAction, detail: String, category: AuditCategory) {
        self.eventID = UUID().uuidString
        self.timestamp = Date()
        self.user = user
        self.role = role
        self.action = action
        self.detail = detail
        self.category = category
    }
}

public enum AuditAction: String, Codable, Sendable {
    case scanStarted = "SCAN_STARTED"
    case scanCompleted = "SCAN_COMPLETED"
    case scanCancelled = "SCAN_CANCELLED"
    case configChanged = "CONFIG_CHANGED"
    case historyDeleted = "HISTORY_DELETED"
    case exportPerformed = "EXPORT_PERFORMED"
    case rulesUpdated = "RULES_UPDATED"
    case apiStarted = "API_STARTED"
    case apiStopped = "API_STOPPED"
    case login = "LOGIN"
    case logout = "LOGOUT"
    case profileApplied = "PROFILE_APPLIED"
    case profileSaved = "PROFILE_SAVED"
    case retentionPurged = "RETENTION_PURGED"
}

public enum AuditCategory: String, Codable, Sendable {
    case scanning = "Scanning"
    case configuration = "Configuration"
    case security = "Security"
    case dataManagement = "Data Management"
    case export = "Export"
    case system = "System"
}

public final class AuditLogger: @unchecked Sendable {
    public static let shared = AuditLogger()
    private let store = ScopedStore()
    private var events: [AuditEvent] = []
    private let lock = OSAllocatedUnfairLock()

    private init() {}

    public func log(user: String = "local", role: UserRole = .admin, action: AuditAction, detail: String, category: AuditCategory) {
        let event = AuditEvent(user: user, role: role, action: action, detail: detail, category: category)
        lock.lock()
        events.append(event)
        if events.count > 1000 { events.removeFirst(events.count - 500) }
        lock.unlock()
        store.save(event: event)
    }

    public func recent(limit: Int = 100) -> [AuditEvent] {
        lock.lock()
        let result = Array(events.suffix(limit))
        lock.unlock()
        return result
    }

    public func export() -> [AuditEvent] {
        store.loadAll()
    }

    public func clear() {
        lock.lock()
        events.removeAll()
        lock.unlock()
        store.clear()
    }
}

private final class ScopedStore: @unchecked Sendable {
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    private var fileURL: URL? {
        guard let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else { return nil }
        let appDir = dir.appendingPathComponent("com.lanscanner")
        try? FileManager.default.createDirectory(at: appDir, withIntermediateDirectories: true)
        return appDir.appendingPathComponent("audit.jsonl")
    }

    func save(event: AuditEvent) {
        guard let url = fileURL, let data = try? encoder.encode(event),
              let line = String(data: data, encoding: .utf8) else { return }
        if let handle = try? FileHandle(forWritingTo: url) {
            handle.seekToEndOfFile()
            try? handle.write(contentsOf: (line + "\n").data(using: .utf8)!)
            try? handle.close()
        } else {
            try? (line + "\n").data(using: .utf8)?.write(to: url, options: .atomic)
        }
    }

    func loadAll() -> [AuditEvent] {
        guard let url = fileURL, let data = try? Data(contentsOf: url),
              let contents = String(data: data, encoding: .utf8) else { return [] }
        return contents.split(separator: "\n").compactMap { line in
            try? decoder.decode(AuditEvent.self, from: Data(line.utf8))
        }
    }

    func clear() {
        guard let url = fileURL else { return }
        try? "".write(to: url, atomically: true, encoding: .utf8)
    }
}
