import Foundation
import Observation
import Core
import NetScan
import Engine

@MainActor
@Observable
public final class ScannerViewModel {
    public var devices: [Device] = []
    public var isScanning = false
    public var progress: Double = 0
    public var statusMessage = "Ready"
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

    private let discovery = NetworkDiscovery()
    private let portScanner = PortScanner()
    private let vulnMapper = VulnMapper()
    private let udpScanner = UDPScanner()
    private let scanStore = ScanStore.shared
    private let alertService = AlertService()
    private var scanTask: Task<Void, Never>?

    public init() {
        Logger.ui.notice("ScannerViewModel initialized")
        loadHistory()
        ScanScheduler.shared.configure { [weak self] in
            await self?.startScan()
        }
        if config.scheduleEnabled {
            ScanScheduler.shared.schedule(intervalHours: config.scheduleIntervalHours)
        }
    }

    public func checkScheduledScan() {
        if config.scheduleEnabled && !ScanScheduler.shared.isScheduled {
            ScanScheduler.shared.schedule(intervalHours: config.scheduleIntervalHours)
            statusMessage = "Scheduled scans active (every \(config.scheduleIntervalHours)h)"
        }
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

    public var filteredDevices: [Device] {
        guard !searchText.isEmpty else { return devices }
        return devices.filter {
            $0.ip.localizedCaseInsensitiveContains(searchText) ||
            ($0.host ?? "").localizedCaseInsensitiveContains(searchText)
        }
    }

    public var riskScore: Double {
        guard !devices.isEmpty else { return 0 }
        let total = devices.reduce(0.0) { $0 + $1.riskScore }
        return total / Double(devices.count)
    }

    public var totalOpenPorts: Int {
        devices.reduce(0) { $0 + $1.ports.filter { $0.state == .open }.count }
    }

    public var totalVulnerabilities: Int {
        devices.reduce(0) { $0 + $1.vulnerabilities.count }
    }

    public func startScan() {
        guard !isScanning else { return }
        isScanning = true
        progress = 0
        statusMessage = "Starting scan..."
        errorMessage = nil
        devices = []
        selectedHistoryScanID = nil
        historyDevices = []

        scanTask = Task { [weak self] in
            guard let self = self else { return }
            let startTime = Date()

            do {
                self.statusMessage = "Discovering network hosts..."
                let discoveredDevices = try await self.discovery.scanSubnet(timeout: 30)
                self.progress = 0.2

                var scannedDevices: [Device] = []
                let total = discoveredDevices.count

                for (index, var device) in discoveredDevices.enumerated() {
                    try Task.checkCancellation()
                    self.statusMessage = "Scanning \(device.ip) (\(index + 1)/\(total))..."

                    let tcpPorts = try await self.portScanner.scan(
                        ip: device.ip,
                        ports: Array(self.config.portRange),
                        timeout: self.config.timeout
                    )

                    var allPorts = tcpPorts

                    if self.config.scanUDP {
                        let udpPorts = try await self.udpScanner.scan(
                            ip: device.ip,
                            ports: Array(self.config.udpPortRange),
                            timeout: self.config.timeout
                        )
                        allPorts.append(contentsOf: udpPorts)
                    }

                    device = Device(
                        ip: device.ip,
                        mac: device.mac,
                        host: device.host,
                        os: device.os,
                        ports: allPorts
                    )

                    let vulns = self.vulnMapper.map(device: device)
                    device = Device(
                        ip: device.ip,
                        mac: device.mac,
                        host: device.host,
                        os: device.os,
                        ports: allPorts,
                        vulnerabilities: vulns
                    )

                    scannedDevices.append(device)
                    self.devices = scannedDevices
                    self.progress = 0.2 + (0.8 * Double(index + 1) / Double(max(total, 1)))
                }

                self.scanDuration = Date().timeIntervalSince(startTime)
                let result = ScanResult(devices: scannedDevices, scanDuration: self.scanDuration, totalPortsScanned: self.config.portRange.count)
                try? self.scanStore.save(scanResult: result, config: self.config, duration: self.scanDuration)
                self.loadHistory()

                self.statusMessage = "Scan complete: \(scannedDevices.count) devices in \(String(format: "%.1f", self.scanDuration))s"
                Logger.ui.notice("Scan completed: \(scannedDevices.count) devices, \(self.scanDuration)s")

                if self.config.webhookEnabled {
                    let summary = ScanSummary(
                        timestamp: result.timestamp,
                        duration: self.scanDuration,
                        deviceCount: scannedDevices.count,
                        totalOpenPorts: self.totalOpenPorts,
                        totalVulnerabilities: self.totalVulnerabilities,
                        riskScore: self.riskScore,
                        config: self.config
                    )
                    Task {
                        await self.alertService.sendScanComplete(scanSummary: summary, devices: scannedDevices, webhookURL: self.config.webhookURL)
                    }
                }
            } catch is CancellationError {
                self.statusMessage = "Scan cancelled"
                Logger.ui.notice("Scan cancelled by user")
            } catch {
                let networkError = NetworkError.from(error)
                self.errorMessage = networkError.errorDescription
                self.statusMessage = "Scan failed"
                Logger.ui.error("Scan failed: \(networkError.localizedDescription)")
            }

            self.isScanning = false
            self.progress = 1.0
        }
    }

    public func stopScan() {
        scanTask?.cancel()
        scanTask = nil
        statusMessage = "Stopping..."
    }

    public func loadHistory() {
        history = scanStore.loadHistory(limit: 50)
        trends = scanStore.computeTrends()
    }

    public func selectHistoryScan(scanID: String) {
        selectedHistoryScanID = scanID
        devices = []
        selectedDevice = nil
        if let loaded = try? scanStore.loadDevices(scanID: scanID) {
            historyDevices = loaded
        }
    }

    public func deleteHistoryScan(scanID: String) {
        try? scanStore.deleteScan(scanID: scanID)
        if selectedHistoryScanID == scanID {
            selectedHistoryScanID = nil
            historyDevices = []
        }
        loadHistory()
    }

    public func exportCSV() -> String {
        let sourceDevices = selectedHistoryScanID != nil ? historyDevices : devices
        var csv = "IP,MAC,Hostname,OS,Risk Score,Open Ports,Vulnerabilities\n"
        for device in sourceDevices {
            let ports = device.ports.filter { $0.state == .open }.map { "\($0.number)/\($0.service ?? "")" }.joined(separator: ";")
            let vulns = device.vulnerabilities.map { "\($0.id)(\(String(format: "%.1f", $0.severity)))" }.joined(separator: ";")
            csv += "\(device.ip),\(device.mac ?? ""),\(device.host ?? ""),\(device.os ?? ""),\(String(format: "%.1f", device.riskScore)),\"\(ports)\",\"\(vulns)\"\n"
        }
        return csv
    }

    public func exportJSON() -> String {
        struct ExportDevice: Codable {
            let ip: String
            let mac: String?
            let host: String?
            let os: String?
            let riskScore: Double
            let openPorts: [ExportPort]
            let vulnerabilities: [ExportVuln]
        }
        struct ExportPort: Codable {
            let port: Int
            let service: String?
            let banner: String?
        }
        struct ExportVuln: Codable {
            let id: String
            let severity: Double
            let description: String
            let recommendation: String?
        }

        let sourceDevices = selectedHistoryScanID != nil ? historyDevices : devices
        let exportDevices = sourceDevices.map { device -> ExportDevice in
            ExportDevice(
                ip: device.ip,
                mac: device.mac,
                host: device.host,
                os: device.os,
                riskScore: device.riskScore,
                openPorts: device.ports.filter { $0.state == .open }.map { ExportPort(port: $0.number, service: $0.service, banner: $0.banner) },
                vulnerabilities: device.vulnerabilities.map { ExportVuln(id: $0.id, severity: $0.severity, description: $0.description, recommendation: $0.recommendation) }
            )
        }

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let data = try? encoder.encode(exportDevices) {
            return String(data: data, encoding: .utf8) ?? "[]"
        }
        return "[]"
    }
}
