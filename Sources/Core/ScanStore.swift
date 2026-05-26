import Foundation

public final class ScanStore: @unchecked Sendable {
    public static let shared = ScanStore()
    private let fileManager = FileManager.default
    private let decoder = JSONDecoder()
    private let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.outputFormatting = [.prettyPrinted, .sortedKeys]
        return e
    }()

    private init() {}

    private var appSupportURL: URL {
        let paths = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask)
        let dir = paths[0].appendingPathComponent("com.lanscanner", isDirectory: true)
        try? fileManager.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private var scansDir: URL {
        let dir = appSupportURL.appendingPathComponent("scans", isDirectory: true)
        try? fileManager.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private var indexPath: URL {
        appSupportURL.appendingPathComponent("index.json")
    }

    // MARK: - Save Scan
    public func save(scanResult: ScanResult, config: ScanConfig, duration: TimeInterval) throws -> String {
        let scanID = UUID().uuidString
        let scanDir = scansDir.appendingPathComponent(scanID, isDirectory: true)
        try fileManager.createDirectory(at: scanDir, withIntermediateDirectories: true)

        let devicesData = try encoder.encode(scanResult.devices)
        try devicesData.write(to: scanDir.appendingPathComponent("devices.json"), options: .atomic)

        let summary = ScanSummary(
            scanID: scanID,
            timestamp: scanResult.timestamp,
            duration: duration,
            deviceCount: scanResult.devices.count,
            totalOpenPorts: scanResult.devices.reduce(0) { $0 + $1.ports.filter { $0.state == .open }.count },
            totalVulnerabilities: scanResult.devices.reduce(0) { $0 + $1.vulnerabilities.count },
            riskScore: scanResult.devices.isEmpty ? 0 : scanResult.devices.reduce(0.0) { $0 + $1.riskScore } / Double(scanResult.devices.count),
            config: config
        )

        var index = try loadIndex()
        index.append(summary)
        index.sort { $0.timestamp > $1.timestamp }
        let indexData = try encoder.encode(index)
        try indexData.write(to: indexPath, options: .atomic)

        Logger.config.notice("Scan saved: \(scanID) (\(scanResult.devices.count) devices)")
        return scanID
    }

    // MARK: - Load Scan
    public func loadDevices(scanID: String) throws -> [Device] {
        let path = scansDir.appendingPathComponent(scanID).appendingPathComponent("devices.json")
        let data = try Data(contentsOf: path)
        return try decoder.decode([Device].self, from: data)
    }

    // MARK: - History
    public func loadHistory() throws -> [ScanSummary] {
        try loadIndex()
    }

    public func loadHistory(limit: Int) -> [ScanSummary] {
        guard let index = try? loadIndex() else { return [] }
        return Array(index.prefix(limit))
    }

    public func deleteScan(scanID: String) throws {
        let scanDir = scansDir.appendingPathComponent(scanID)
        try? fileManager.removeItem(at: scanDir)
        var index = try loadIndex()
        index.removeAll { $0.scanID == scanID }
        let indexData = try encoder.encode(index)
        try indexData.write(to: indexPath, options: .atomic)
        Logger.config.notice("Scan deleted: \(scanID)")
    }

    // MARK: - Trends
    public func computeTrends() -> TrendData {
        guard let index = try? loadIndex(), !index.isEmpty else {
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

    // MARK: - Internal
    private func loadIndex() throws -> [ScanSummary] {
        guard fileManager.fileExists(atPath: indexPath.path) else { return [] }
        let data = try Data(contentsOf: indexPath)
        return try decoder.decode([ScanSummary].self, from: data)
    }
}
