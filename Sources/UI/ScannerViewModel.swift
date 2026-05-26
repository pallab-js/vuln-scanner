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

    private let discovery = NetworkDiscovery()
    private let portScanner = PortScanner()
    private let vulnMapper = VulnMapper()
    private var scanTask: Task<Void, Never>?

    public init() {
        Logger.ui.notice("ScannerViewModel initialized")
    }

    public func startScan() {
        guard !isScanning else { return }
        isScanning = true
        progress = 0
        statusMessage = "Starting scan..."
        errorMessage = nil
        devices = []

        scanTask = Task { [weak self] in
            guard let self = self else { return }
            let startTime = Date()

            do {
                self.statusMessage = "Discovering network hosts..."
                let discoveredDevices = try await self.discovery.scanSubnet(timeout: 30)
                self.progress = 0.3

                var scannedDevices: [Device] = []
                let total = discoveredDevices.count

                for (index, var device) in discoveredDevices.enumerated() {
                    try Task.checkCancellation()
                    self.statusMessage = "Scanning \(device.ip) (\(index + 1)/\(total))..."

                    let ports = try await self.portScanner.scan(
                        ip: device.ip,
                        ports: Array(self.config.portRange),
                        timeout: self.config.timeout
                    )

                    device = Device(
                        ip: device.ip,
                        mac: device.mac,
                        host: device.host,
                        os: device.os,
                        ports: ports
                    )

                    let vulns = self.vulnMapper.map(device: device)
                    device = Device(
                        ip: device.ip,
                        mac: device.mac,
                        host: device.host,
                        os: device.os,
                        ports: ports,
                        vulnerabilities: vulns
                    )

                    scannedDevices.append(device)
                    self.devices = scannedDevices
                    self.progress = 0.3 + (0.7 * Double(index + 1) / Double(max(total, 1)))
                }

                self.scanDuration = Date().timeIntervalSince(startTime)
                self.statusMessage = "Scan complete: \(scannedDevices.count) devices in \(String(format: "%.1f", self.scanDuration))s"
                Logger.ui.notice("Scan completed: \(scannedDevices.count) devices, \(self.scanDuration)s")
            } catch is CancellationError {
                self.statusMessage = "Scan cancelled"
                Logger.ui.notice("Scan cancelled by user")
            } catch {
                self.errorMessage = error.localizedDescription
                self.statusMessage = "Scan failed"
                Logger.ui.error("Scan failed: \(error.localizedDescription)")
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

    public func exportCSV() -> String {
        var csv = "IP,MAC,Hostname,OS,Open Ports,Vulnerabilities\n"
        for device in devices {
            let ports = device.ports.filter { $0.state == .open }.map { "\($0.number)/\($0.service ?? "")" }.joined(separator: ";")
            let vulns = device.vulnerabilities.map { "\($0.id)(\(String(format: "%.1f", $0.severity)))" }.joined(separator: ";")
            csv += "\(device.ip),\(device.mac ?? ""),\(device.host ?? ""),\(device.os ?? ""),\"\(ports)\",\"\(vulns)\"\n"
        }
        return csv
    }

    public var totalOpenPorts: Int {
        devices.reduce(0) { $0 + $1.ports.filter { $0.state == .open }.count }
    }

    public var totalVulnerabilities: Int {
        devices.reduce(0) { $0 + $1.vulnerabilities.count }
    }
}
