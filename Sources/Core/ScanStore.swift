import Foundation
import GRDB

/// SQLite persistence for scan results and history.
/// @unchecked Sendable is safe because all mutable state is accessed
/// through GRDB's DatabaseQueue which is thread-safe.
public final class ScanStore: @unchecked Sendable {
    public static let shared = ScanStore()
    private var db: DatabaseQueue
    private let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.outputFormatting = [.prettyPrinted, .sortedKeys]
        return e
    }()
    private let decoder = JSONDecoder()

    enum StoreInitError: Error, LocalizedError {
        case databaseUnavailable(String)
        var errorDescription: String? {
            switch self { case .databaseUnavailable(let path): return "Scan database unavailable at \(path)" }
        }
    }

    private init() {
        let paths = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)
        let dir = paths[0].appendingPathComponent("com.lanscanner", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let dbPath = dir.appendingPathComponent("scans.db").path
        guard let queue = try? DatabaseQueue(path: dbPath) else {
            Logger.config.error("Failed to open database at \(dbPath), using in-memory fallback")
            self.db = try! DatabaseQueue()
            Logger.config.notice("ScanStore initialized with in-memory SQLite (persistence disabled)")
            return
        }
        self.db = queue
        do {
            try db.write { db in
                try db.create(table: "scans", ifNotExists: true) { t in
                    t.column("scan_id", .text).primaryKey()
                    t.column("timestamp", .datetime).notNull()
                    t.column("duration", .double).notNull()
                    t.column("device_count", .integer).notNull()
                    t.column("total_open_ports", .integer).notNull()
                    t.column("total_vulnerabilities", .integer).notNull()
                    t.column("risk_score", .double).notNull()
                    t.column("config_json", .text).notNull()
                    t.column("devices_json", .text).notNull()
                }
            }
            Logger.config.notice("ScanStore initialized with SQLite at \(dbPath)")
        } catch {
            Logger.config.error("Failed to create schema: \(error.localizedDescription), using in-memory fallback")
            self.db = try! DatabaseQueue()
            Logger.config.notice("ScanStore initialized with in-memory SQLite (persistence disabled)")
        }
    }

    // MARK: - Save Scan
    public func save(scanResult: ScanResult, config: ScanConfig, duration: TimeInterval) throws -> String {
        let scanID = UUID().uuidString
        let devicesData = try encoder.encode(scanResult.devices)
        let devicesJSON = String(data: devicesData, encoding: .utf8)!
        let configData = try encoder.encode(config)
        let configJSON = String(data: configData, encoding: .utf8)!

        let summary = ScanSummary(
            scanID: scanID,
            timestamp: scanResult.timestamp,
            duration: duration,
            deviceCount: scanResult.devices.count,
            totalOpenPorts: scanResult.devices.reduce(0) { $0 + $1.ports.filter { $0.state == .open }.count },
            totalVulnerabilities: scanResult.devices.reduce(0) { $0 + $1.vulnerabilities.count },
            riskScore: scanResult.devices.map(\.riskScore).max() ?? 0,
            config: config
        )

        try db.write { db in
            try db.execute(sql: """
                INSERT INTO scans (scan_id, timestamp, duration, device_count, total_open_ports,
                                   total_vulnerabilities, risk_score, config_json, devices_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, arguments: [
                    scanID, summary.timestamp, summary.duration, summary.deviceCount,
                    summary.totalOpenPorts, summary.totalVulnerabilities, summary.riskScore,
                    configJSON, devicesJSON,
                ])
        }

        Logger.config.notice("Scan saved: \(scanID) (\(scanResult.devices.count) devices)")
        return scanID
    }

    // MARK: - Load Scan
    public func loadDevices(scanID: String) throws -> [Device] {
        let row = try db.read { db in
            try Row.fetchOne(db, sql: "SELECT devices_json FROM scans WHERE scan_id = ?", arguments: [scanID])
        }
        guard let json = row?["devices_json"] as? String, let data = json.data(using: .utf8) else {
            throw ScanStoreError.scanNotFound
        }
        return try decoder.decode([Device].self, from: data)
    }

    // MARK: - History
    private func rowToSummary(_ row: Row) -> ScanSummary? {
        guard let configData = row["config_json"] as? String,
              let configDataObj = configData.data(using: .utf8),
              let config = try? decoder.decode(ScanConfig.self, from: configDataObj) else {
            Logger.config.error("Skipping corrupt scan record: \(row["scan_id"] ?? "unknown")")
            return nil
        }
        return ScanSummary(
            scanID: row["scan_id"], timestamp: row["timestamp"], duration: row["duration"],
            deviceCount: row["device_count"], totalOpenPorts: row["total_open_ports"],
            totalVulnerabilities: row["total_vulnerabilities"], riskScore: row["risk_score"],
            config: config
        )
    }

    public func loadHistory() throws -> [ScanSummary] {
        try db.read { db in
            let rows = try Row.fetchAll(db, sql: "SELECT * FROM scans ORDER BY timestamp DESC")
            return rows.compactMap { self.rowToSummary($0) }
        }
    }

    public func loadHistory(limit: Int) -> [ScanSummary] {
        guard let result = try? db.read({ db in
            let rows = try Row.fetchAll(db, sql: "SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?", arguments: [limit])
            return rows.compactMap { self.rowToSummary($0) }
        }) else { return [] }
        return result
    }

    @discardableResult
    public func deleteOlderThan(_ date: Date) -> Int {
        guard let count = try? db.write({ db in
            try db.execute(sql: "DELETE FROM scans WHERE timestamp < ?", arguments: [date])
            return db.changesCount
        }) else { return 0 }
        return count
    }

    @discardableResult
    public func trim(toMax maxCount: Int) -> Int {
        guard let total = try? db.read({ db in
            try Int.fetchOne(db, sql: "SELECT COUNT(*) FROM scans") ?? 0
        }), total > maxCount else { return 0 }
        let excess = total - maxCount
        guard let deleted = try? db.write({ db in
            try db.execute(sql: "DELETE FROM scans WHERE scan_id IN (SELECT scan_id FROM scans ORDER BY timestamp ASC LIMIT ?)", arguments: [excess])
            return db.changesCount
        }) else { return 0 }
        return deleted
    }

    public func deleteScan(scanID: String) throws {
        try db.write { db in
            try db.execute(sql: "DELETE FROM scans WHERE scan_id = ?", arguments: [scanID])
        }
        Logger.config.notice("Scan deleted: \(scanID)")
    }

    // MARK: - Trends
    public func computeTrends() -> TrendData {
        guard let index = try? loadHistory(), !index.isEmpty else {
            return TrendData(totalScans: 0, vulnsOverTime: [], devicesOverTime: [], riskOverTime: [], topCVE: [])
        }

        let vulnsOverTime = index.map { TrendPoint(date: $0.timestamp, metric: "vulns", value: Double($0.totalVulnerabilities)) }
        let devicesOverTime = index.map { TrendPoint(date: $0.timestamp, metric: "devices", value: Double($0.deviceCount)) }
        let riskOverTime = index.map { TrendPoint(date: $0.timestamp, metric: "risk", value: $0.riskScore) }

        var cveCounts: [String: Int] = [:]
        for summary in index {
            guard let devices = try? loadDevices(scanID: summary.scanID) else { continue }
            for device in devices {
                for vuln in device.vulnerabilities {
                    if let cve = vuln.cve {
                        cveCounts[cve, default: 0] += 1
                    }
                }
            }
        }
        let topCVE = cveCounts.sorted { $0.value > $1.value }.prefix(10).map { CVECount(cve: $0.key, count: $0.value) }

        return TrendData(
            totalScans: index.count,
            vulnsOverTime: vulnsOverTime,
            devicesOverTime: devicesOverTime,
            riskOverTime: riskOverTime,
            topCVE: topCVE
        )
    }
}

enum ScanStoreError: Error {
    case scanNotFound
}
