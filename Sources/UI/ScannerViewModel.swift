import Foundation
import Observation
import SwiftUI
import Core
import NetScan
import Engine
import API

@MainActor
@Observable
public final class ScannerViewModel {
    public var devices: [Device] = []
    public var isScanning = false
    public var progress: Double = 0
    public var statusMessage = ""
    public var scanDuration: TimeInterval = 0
    public var errorMessage: String?
    public var selectedDevice: Device?
    public var config = ScanConfig.default
    public var searchText = ""
    public var showConfig = false
    public var history: [ScanSummary] = []
    public var trends = TrendData(totalScans: 0, vulnsOverTime: [], devicesOverTime: [], riskOverTime: [], topCVE: [])
    public var selectedHistoryScanID: String?
    public var historyDevices: [Device] = []
    public var activeComplianceFilters: Set<ComplianceFramework> = []
    public var customRules: [CustomRule] = []
    public var showRuleEditor = false
    public var editingRule: CustomRule?
    public var showRulesManager = false
    public var deviceTags: [String: [Tag]] = [:]
    public var tagFilter: String?
    public var showTagEditor = false
    public var editingTagDevice: String? = nil
    public var rulesVersion: Int = 0
    public var isUpdatingRules = false
    public var peakMemoryMB: Double = 0
    public var currentMemoryMB: Double = 0
    public var rulesUpdateError: String?
    public var showRulesUpdateConfig = false

    // Tier 2 enhancements
    public var selectedSeverityFilter: SeverityLevel? = nil
    public var showCompareView = false
    public var compareBaseline: [Device] = []
    public var toastMessage: String?
    public var toastIcon = "checkmark.circle.fill"
    public var toastColor: Color = .green
    public var isShowingToast = false
    public var showExportPreview = false
    public var exportPreviewContent = ""
    public var exportPreviewFormat = ""
    public var exportSaveAction: (() -> Void)?
    public var historyLoadCount = 10
    public var multiSelectedIPs: Set<String> = []

    // Tier 3 additions
    public var isAuthenticated = false
    public var needsAuth = false
    public var userRole: UserRole = .admin
    public var showAuditLog = false
    public var showProfiles = false
    public var selectedProfile: String?
    public var retentionPolicy = RetentionManager.shared.policy
    public var deliveryConfig = ReportDelivery.shared.config
    public var siemConfig = SIEMConfig.default

    // scan source tracking
    public var scanSource: ScanSource = .current

    public enum ScanSource: String, CaseIterable {
        case current = "Live"
        case history = "History"
    }

    public var complianceSummary: String {
        guard !activeComplianceFilters.isEmpty else { return "All frameworks" }
        return activeComplianceFilters.map(\.rawValue).sorted().joined(separator: ", ")
    }

    public var isViewingHistory: Bool { scanSource == .history && selectedHistoryScanID != nil }

    public var sourceDevices: [Device] {
        isViewingHistory ? historyDevices : devices
    }

    public func vulnsMatchingCompliance(_ vulns: [Vuln]) -> [Vuln] {
        guard !activeComplianceFilters.isEmpty else { return vulns }
        return vulns.filter { !Set($0.compliance).isDisjoint(with: activeComplianceFilters) }
    }

    private let orchestrator = ScanOrchestrator()
    private let scanStore = ScanStore.shared
    private let alertService = AlertService()

    public init() {
        Logger.ui.notice("ScannerViewModel initialized")
        customRules = CustomRulesStore.shared.load()
        deviceTags = TagStore.shared.load()
        rulesVersion = RuleLoader.currentVersion
        loadHistory()
        if RetentionManager.shared.policy.autoPurgeOnLaunch {
            RetentionManager.shared.enforce(on: scanStore)
            loadHistory()
        }
        ScanScheduler.shared.configure { [weak self] in
            await self?.startScan()
        }
        if config.scheduleEnabled {
            ScanScheduler.shared.schedule(intervalHours: config.scheduleIntervalHours)
        }
        if config.apiEnabled {
            RESTServer.shared.port = config.apiPort
            RESTServer.shared.apiKey = config.apiKey
            Task {
                try? await RESTServer.shared.start()
            }
        }
    }

    public func checkScheduledScan() {
        if config.scheduleEnabled && !ScanScheduler.shared.isScheduled {
            ScanScheduler.shared.schedule(intervalHours: config.scheduleIntervalHours)
            statusMessage = "Scheduled scans active (every \(config.scheduleIntervalHours)h)"
        }
    }

    public func updateAPI(enabled: Bool, port: Int, apiKey: String = "") {
        config.apiEnabled = enabled
        config.apiPort = port
        config.apiKey = apiKey
        if enabled {
            RESTServer.shared.port = port
            RESTServer.shared.apiKey = apiKey
            Task {
                do {
                    try await RESTServer.shared.start()
                    statusMessage = "REST API running on port \(port)"
                    AuditLogger.shared.log(action: .apiStarted, detail: "API started on port \(port)", category: .configuration)
                } catch {
                    errorMessage = "Failed to start API: \(error.localizedDescription)"
                    statusMessage = "API failed to start"
                    Logger.ui.error("API start failed: \(error.localizedDescription)")
                }
            }
        } else {
            RESTServer.shared.stop()
            RESTServer.shared.apiKey = ""
            statusMessage = "REST API stopped"
            AuditLogger.shared.log(action: .apiStopped, detail: "API stopped", category: .configuration)
        }
        saveConfig()
    }

    public func updateSchedule(enabled: Bool, intervalHours: Double) {
        config.scheduleEnabled = enabled
        config.scheduleIntervalHours = intervalHours
        if enabled {
            ScanScheduler.shared.schedule(intervalHours: intervalHours)
            statusMessage = "Scheduled every \(intervalHours)h"
        } else {
            ScanScheduler.shared.cancel()
            statusMessage = "Scheduled scans disabled"
        }
        saveConfig()
    }

    private func saveConfig() {
        let encoder = JSONEncoder()
        if let data = try? encoder.encode(config) {
            let url = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
                .appendingPathComponent("com.lanscanner/config.json")
            try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try? data.write(to: url, options: .atomic)
        }
    }

    // MARK: - Profile Management
    public func applyProfile(_ name: String) {
        guard let profileConfig = ProfileManager.shared.apply(name: name) else {
            errorMessage = "Profile '\(name)' not found"
            return
        }
        config = profileConfig
        statusMessage = "Applied profile: \(name)"
        showToast(message: "Applied profile: \(name)")
    }

    public func saveProfile(name: String, description: String = "") {
        ProfileManager.shared.save(name: name, config: config, description: description)
        showToast(message: "Profile saved: \(name)")
    }

    // MARK: - Audit Log
    public var auditEvents: [AuditEvent] { AuditLogger.shared.recent() }

    public func exportAuditLog() -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(AuditLogger.shared.export()) else { return "[]" }
        return String(data: data, encoding: .utf8) ?? "[]"
    }

    // MARK: - Filtering & Search
    public var filteredDevices: [Device] {
        var result = sourceDevices
        if !searchText.isEmpty {
            result = result.filter {
                $0.ip.localizedCaseInsensitiveContains(searchText) ||
                ($0.host ?? "").localizedCaseInsensitiveContains(searchText)
            }
        }
        if let severity = selectedSeverityFilter {
            result = result.filter { device in
                device.vulnerabilities.contains { SeverityLevel.from(score: $0.severity) == severity }
            }
        }
        return result
    }

    public var filteredDevicesWithTags: [Device] {
        var result = filteredDevices
        if let tagFilter {
            result = result.filter { device in
                deviceTags[device.ip]?.contains(where: { $0.name == tagFilter }) ?? false
            }
        }
        return result
    }

    public var riskScore: Double {
        sourceDevices.map(\.riskScore).max() ?? 0
    }

    public var totalOpenPorts: Int {
        sourceDevices.reduce(0) { $0 + $1.ports.filter { $0.state == .open }.count }
    }

    public var totalVulnerabilities: Int {
        sourceDevices.reduce(0) { $0 + $1.vulnerabilities.count }
    }

    // MARK: - Severity Filter from Chart
    public func toggleSeverityFilter(_ level: SeverityLevel) {
        if selectedSeverityFilter == level {
            selectedSeverityFilter = nil
        } else {
            selectedSeverityFilter = level
        }
    }

    // MARK: - Toast
    public func showToast(message: String, icon: String = "checkmark.circle.fill", color: Color = .green) {
        toastMessage = message
        toastIcon = icon
        toastColor = color
        isShowingToast = true
    }

    // MARK: - Rules
    public func updateRules() {
        guard !isUpdatingRules else { return }
        let urlString = config.rulesURL
        guard !urlString.isEmpty else {
            rulesUpdateError = "No rules URL configured"
            return
        }
        isUpdatingRules = true
        rulesUpdateError = nil
        statusMessage = "Updating rules..."
        Task {
            do {
                _ = try await RuleUpdater.update(from: urlString)
                rulesVersion = RuleLoader.currentVersion
                statusMessage = "Rules updated to v\(rulesVersion)"
                AuditLogger.shared.log(action: .rulesUpdated, detail: "Rules updated to v\(rulesVersion)", category: .configuration)
            } catch {
                rulesUpdateError = error.localizedDescription
                statusMessage = "Rules update failed"
                Logger.ui.error("Rules update failed: \(error.localizedDescription)")
            }
            isUpdatingRules = false
        }
    }

    // MARK: - Scanning
    public func startScan() {
        guard !orchestrator.isScanning else { return }
        guard AuthManager.shared.requireRole(.operator_) else {
            errorMessage = "Your role does not allow scanning"
            return
        }

        isScanning = true
        errorMessage = nil
        devices = []
        scanSource = .current
        selectedHistoryScanID = nil
        historyDevices = []
        selectedSeverityFilter = nil
        progress = 0
        statusMessage = "Starting scan..."
        peakMemoryMB = 0

        AuditLogger.shared.log(action: .scanStarted, detail: "Scan started: ports \(config.portRange), timeout \(config.timeout)s", category: .scanning)

        orchestrator.startScan(
            config: config,
            customRules: customRules,
            onRulesUpdate: { [weak self] status in
                self?.statusMessage = status
            },
            onDiscovery: { [weak self] discovered in
                self?.statusMessage = "\(discovered.count) hosts found, scanning ports..."
            },
            onDeviceProgress: { _, _, _ in },
            onProgress: { [weak self] scannedDevices, progress, status in
                self?.devices = scannedDevices
                self?.progress = progress
                self?.statusMessage = status
            },
            onMemory: { [weak self] current, peak in
                self?.currentMemoryMB = current
                self?.peakMemoryMB = peak
            },
            onCompletion: { [weak self] scannedDevices, duration, error in
                guard let self = self else { return }
                self.scanDuration = duration
                self.isScanning = false
                self.progress = 1.0

                if let error = error {
                    if error == "cancelled" {
                        self.statusMessage = "Scan cancelled"
                        AuditLogger.shared.log(action: .scanCancelled, detail: "Scan cancelled by user", category: .scanning)
                    } else {
                        self.errorMessage = error
                        self.statusMessage = "Scan failed"
                        AuditLogger.shared.log(action: .scanCompleted, detail: "Scan failed: \(error)", category: .scanning)
                    }
                    return
                }

                let result = ScanResult(devices: scannedDevices, scanDuration: duration, totalPortsScanned: config.portRange.count)
                _ = try? scanStore.save(scanResult: result, config: config, duration: duration)
                loadHistory()

                statusMessage = "Scan complete: \(scannedDevices.count) devices in \(String(format: "%.1f", duration))s"
                Logger.ui.notice("Scan completed: \(scannedDevices.count) devices, \(duration)s")
                AuditLogger.shared.log(action: .scanCompleted, detail: "\(scannedDevices.count) devices, \(duration)s", category: .scanning)

                if config.webhookEnabled {
                    let summary = ScanSummary(
                        timestamp: result.timestamp,
                        duration: duration,
                        deviceCount: scannedDevices.count,
                        totalOpenPorts: totalOpenPorts,
                        totalVulnerabilities: totalVulnerabilities,
                        riskScore: riskScore,
                        config: config
                    )
                    Task {
                        await alertService.sendScanComplete(scanSummary: summary, devices: scannedDevices, webhookURL: config.webhookURL)
                    }
                }

                if !ReportDelivery.shared.config.slackWebhook.isEmpty || ReportDelivery.shared.config.emailEnabled {
                    let report = ReportGenerator().generateHTML(devices: scannedDevices, scanDuration: duration, timestamp: result.timestamp, config: config)
                    Task {
                        if let err = await ReportDelivery.shared.send(report: report, format: ReportDelivery.shared.config.format, title: "Scan Complete - \(Date().formatted())") {
                            Logger.ui.error("Report delivery failed: \(err.localizedDescription)")
                        }
                    }
                }
            }
        )
    }

    // MARK: - Tags
    public func addTag(_ name: String, color: String, to ip: String) {
        let tag = Tag(name: name, color: color)
        TagStore.shared.addTag(tag, to: ip)
        deviceTags = TagStore.shared.load()
    }

    public func removeTag(_ tag: Tag, from ip: String) {
        TagStore.shared.removeTag(tag, from: ip)
        deviceTags = TagStore.shared.load()
    }

    public var allKnownTags: [Tag] {
        TagStore.shared.allTags()
    }

    public func stopScan() {
        orchestrator.stopScan()
        isScanning = false
        statusMessage = "Stopping..."
    }

    public func loadHistory() {
        history = scanStore.loadHistory(limit: 200)
        historyLoadCount = min(20, history.count)
        trends = scanStore.computeTrends()
    }

    public var isLoadingMoreHistory = false

    public func loadMoreHistory() {
        guard !isLoadingMoreHistory else { return }
        isLoadingMoreHistory = true
        historyLoadCount += 20
        Task { try? await Task.sleep(for: .seconds(0.3)); isLoadingMoreHistory = false }
    }

    public func selectHistoryScan(scanID: String) {
        selectedHistoryScanID = scanID
        scanSource = .history
        devices = []
        selectedDevice = nil
        selectedSeverityFilter = nil
        if let loaded = try? scanStore.loadDevices(scanID: scanID) {
            historyDevices = loaded
        }
    }

    public func switchToCurrentScan() {
        scanSource = .current
        selectedHistoryScanID = nil
        historyDevices = []
        selectedDevice = nil
    }

    public func deleteHistoryScan(scanID: String) {
        try? scanStore.deleteScan(scanID: scanID)
        AuditLogger.shared.log(action: .historyDeleted, detail: "Deleted scan \(scanID)", category: .dataManagement)
        if selectedHistoryScanID == scanID {
            selectedHistoryScanID = nil
            scanSource = .current
            historyDevices = []
        }
        loadHistory()
    }

    // MARK: - Comparison
    public func prepareComparison() {
        compareBaseline = sourceDevices
        showCompareView = true
    }

    // MARK: - Multi-select
    public func batchTag(ip: String, tagName: String, color: String) {
        addTag(tagName, color: color, to: ip)
    }

    public func batchExportSelected() -> String {
        let selected = sourceDevices.filter { multiSelectedIPs.contains($0.ip) }
        let data = selected.map(mapToExportDevice)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let json = try? encoder.encode(data) else { return "[]" }
        return String(data: json, encoding: .utf8) ?? "[]"
    }

    // MARK: - Retention
    public func applyRetentionPolicy() {
        RetentionManager.shared.policy = retentionPolicy
        RetentionManager.shared.enforce(on: scanStore)
        loadHistory()
        showToast(message: "Retention policy applied")
    }

    // MARK: - Export
    public func exportHTML() -> String {
        let generator = ReportGenerator()
        return generator.generateHTML(devices: sourceDevices, scanDuration: scanDuration, timestamp: Date(), config: config)
    }

    public func exportCSV() -> String {
        var csv = "IP,MAC,Hostname,OS,Risk Score,Open Ports,Vulnerabilities\n"
        for device in sourceDevices {
            let ports = device.ports.filter { $0.state == .open }.map { "\($0.number)/\($0.service ?? "")" }.joined(separator: ";")
            let vulns = device.vulnerabilities.map { "\($0.id)(\(String(format: "%.1f", $0.severity)))" }.joined(separator: ";")
            csv += "\(device.ip),\(device.mac ?? ""),\(device.host ?? ""),\(device.os ?? ""),\(String(format: "%.1f", device.riskScore)),\"\(ports)\",\"\(vulns)\"\n"
        }
        return csv
    }

    public func exportJSON() -> String {
        let exportDevices = sourceDevices.map(mapToExportDevice)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let data = try? encoder.encode(exportDevices) {
            return String(data: data, encoding: .utf8) ?? "[]"
        }
        return "[]"
    }

    public func exportSIEM(format: SIEMFormat) -> String {
        SIEMExporter.shared.export(devices: sourceDevices, format: format)
    }

    public func showExportPreview(_ content: String, format: String, saveAction: @escaping () -> Void) {
        exportPreviewContent = content
        exportPreviewFormat = format
        exportSaveAction = saveAction
        showExportPreview = true
    }
}
