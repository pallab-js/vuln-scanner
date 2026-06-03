import Foundation
import Core
import NetScan
import Engine

@MainActor
public final class ScanOrchestrator {
    private let discovery = NetworkDiscovery()
    private let portScanner = PortScanner()
    private let vulnMapper = VulnMapper()
    private let osFingerprinter = OSFingerprinter()
    private let udpScanner = UDPScanner()
    private var scanTask: Task<Void, Never>?

    public private(set) var isScanning = false

    public init() {}

    public func startScan(
        config: ScanConfig,
        customRules: [CustomRule],
        onRulesUpdate: @escaping (String) -> Void,
        onDiscovery: @escaping ([Device]) -> Void,
        onDeviceProgress: @escaping (Device, Int, Int) -> Void,
        onProgress: @escaping ([Device], Double, String) -> Void,
        onMemory: @escaping (Double, Double) -> Void,
        onCompletion: @escaping ([Device], TimeInterval, String?) -> Void
    ) {
        guard !isScanning else { return }
        isScanning = true

        scanTask = Task { [weak self] in
            guard let self = self else { return }

            if config.autoUpdateRules && !config.rulesURL.isEmpty {
                onRulesUpdate("Updating vulnerability rules...")
                do {
                    _ = try await RuleUpdater.update(from: config.rulesURL)
                    Logger.ui.notice("Rules auto-updated to v\(RuleLoader.currentVersion)")
                } catch {
                    Logger.ui.notice("Rules auto-update failed: \(error.localizedDescription)")
                }
            }

            let startTime = Date()

            do {
                onProgress([], 0, "Discovering network hosts...")
                let discoveredDevices = try await self.discovery.scanSubnet(timeout: 30, cidrOverride: config.subnetCIDR)
                onDiscovery(discoveredDevices)
                onProgress([], 0.2, "\(discoveredDevices.count) hosts found, scanning ports...")

                var scannedDevices: [Device] = []
                let total = discoveredDevices.count

                for (index, var device) in discoveredDevices.enumerated() {
                    try Task.checkCancellation()

                    let tcpPorts = try await self.portScanner.scan(
                        ip: device.ip,
                        ports: Array(config.portRange),
                        timeout: config.timeout
                    )

                    var allPorts = tcpPorts

                    if config.scanUDP {
                        let udpPorts = try await self.udpScanner.scan(
                            ip: device.ip,
                            ports: Array(config.udpPortRange),
                            timeout: config.timeout
                        )
                        allPorts.append(contentsOf: udpPorts)
                    }

                    let inferredOS = self.osFingerprinter.infer(ports: allPorts)
                    let resolvedOS = device.os ?? inferredOS

                    device = Device(
                        ip: device.ip,
                        mac: device.mac,
                        host: device.host,
                        os: resolvedOS,
                        ports: allPorts,
                        firstSeen: device.firstSeen,
                        lastSeen: device.lastSeen
                    )

                    let vulns = self.vulnMapper.map(device: device, customRules: customRules)
                    device = Device(
                        ip: device.ip,
                        mac: device.mac,
                        host: device.host,
                        os: resolvedOS,
                        ports: allPorts,
                        vulnerabilities: vulns,
                        firstSeen: device.firstSeen,
                        lastSeen: device.lastSeen
                    )

                    scannedDevices.append(device)
                    let progress = 0.2 + (0.8 * Double(index + 1) / Double(max(total, 1)))
                    let currentMem = MemoryTracker.shared.currentRSSMB
                    let peakMem = scannedDevices.map { _ in currentMem }.max() ?? currentMem

                    onProgress(scannedDevices, progress, "Scanning \(device.ip) (\(index + 1)/\(total))...")
                    onDeviceProgress(device, index, total)
                    onMemory(currentMem, peakMem)
                }

                let duration = Date().timeIntervalSince(startTime)
                onProgress(scannedDevices, 1.0, "Scan complete: \(scannedDevices.count) devices in \(String(format: "%.1f", duration))s")
                onCompletion(scannedDevices, duration, nil)

            } catch is CancellationError {
                Logger.ui.notice("Scan cancelled by user")
                onCompletion([], Date().timeIntervalSince(startTime), "cancelled")
            } catch {
                let networkError = NetworkError.from(error)
                Logger.ui.error("Scan failed: \(networkError.localizedDescription)")
                onCompletion([], Date().timeIntervalSince(startTime), networkError.errorDescription)
            }

            self.isScanning = false
        }
    }

    public func stopScan() {
        scanTask?.cancel()
        scanTask = nil
        isScanning = false
    }
}
