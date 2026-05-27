import SwiftUI
import Core
import NetScan
import Engine
import UI

@main
struct LANScannerApp: App {
    init() {
        registerServices()

        if CommandLine.arguments.contains("--scan") || CommandLine.arguments.contains("--scheduled-scan") {
            CLIRunner.runAndExit()
        }

        Logger.lifecycle.notice("LANScanner starting GUI")

        ScanScheduler.shared.configure {
            await CLIRunner.runScan(cidr: nil, isScheduled: true)
        }
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .frame(minWidth: 800, minHeight: 600)
        }
        .windowResizability(.contentMinSize)
        .commands {
            CommandGroup(replacing: .appInfo) {
                Button("About LAN Scanner") {
                    Logger.app.info("About menu selected")
                }
            }
        }
    }

    private func registerServices() {
        let container = DIContainer.shared
        container.registerSingleton(AppState.self) { _ in
            AppState()
        }
        Logger.lifecycle.debug("Services registered")
    }
}

// MARK: - CLI Runner
enum CLIRunner {
    static func runAndExit() {
        let args = Array(CommandLine.arguments.dropFirst())
        var cidr: String?
        var outputPath: String?
        let isScheduled = args.contains("--scheduled-scan")

        var i = args.startIndex
        while i < args.endIndex {
            switch args[i] {
            case "--subnet" where i + 1 < args.endIndex:
                cidr = args[i + 1]; i += 2
            case "--output" where i + 1 < args.endIndex:
                outputPath = args[i + 1]; i += 2
            default:
                i += 1
            }
        }

        let semaphore = DispatchSemaphore(value: 0)
        Task {
            await runScan(cidr: cidr, outputPath: outputPath, isScheduled: isScheduled)
            semaphore.signal()
        }
        semaphore.wait()
        exit(0)
    }

    static func runScan(cidr: String? = nil, outputPath: String? = nil, isScheduled: Bool = false) async {
        Logger.app.notice("Headless scan starting\(cidr.map { " on \($0)" } ?? "")")

        let discovery = NetworkDiscovery()
        let scanner = PortScanner()
        let udpScanner = UDPScanner()
        let mapper = VulnMapper()
        let fingerprinter = OSFingerprinter()
        let store = ScanStore.shared
        let alert = AlertService()
        let config = ScanConfig.default

        do {
            let startTime = Date()
            let devices = try await discovery.scanSubnet(timeout: 30, cidrOverride: cidr)
            var scannedDevices: [Device] = []

            for var device in devices {
                let ports = try await scanner.scan(ip: device.ip, ports: Array(config.portRange), timeout: config.timeout)
                var allPorts = ports
                if config.scanUDP {
                    let udpPorts = try await udpScanner.scan(ip: device.ip, ports: Array(config.udpPortRange), timeout: config.timeout)
                    allPorts.append(contentsOf: udpPorts)
                }

                let os = device.os ?? fingerprinter.infer(ports: allPorts)
                device = Device(ip: device.ip, mac: device.mac, host: device.host, os: os, ports: allPorts)
                let vulns = mapper.map(device: device)
                device = Device(ip: device.ip, mac: device.mac, host: device.host, os: os, ports: allPorts, vulnerabilities: vulns)
                scannedDevices.append(device)
            }

            let duration = Date().timeIntervalSince(startTime)
            let totalOpen = scannedDevices.reduce(0) { $0 + $1.ports.filter { $0.state == .open }.count }
            let totalVulns = scannedDevices.reduce(0) { $0 + $1.vulnerabilities.count }
            let avgRisk = scannedDevices.isEmpty ? 0 : scannedDevices.reduce(0.0) { $0 + $1.riskScore } / Double(scannedDevices.count)
            let result = ScanResult(devices: scannedDevices, scanDuration: duration, totalPortsScanned: config.portRange.count)
            _ = try? store.save(scanResult: result, config: config, duration: duration)

            let report = ReportGenerator().generateHTML(devices: scannedDevices, scanDuration: duration, timestamp: result.timestamp, config: config)

            if let path = outputPath {
                if path.hasSuffix(".json") {
                    let json = exportJSON(devices: scannedDevices)
                    try? json.write(to: URL(fileURLWithPath: path), atomically: true, encoding: .utf8)
                } else {
                    try? report.write(to: URL(fileURLWithPath: path), atomically: true, encoding: .utf8)
                }
                print("Report: \(path)")
            }

            print("Scan: \(scannedDevices.count) devices, \(totalOpen) open ports, \(totalVulns) vulns, risk \(String(format: "%.1f", avgRisk)) [\(String(format: "%.1f", duration))s]")
            for d in scannedDevices.sorted(by: { $0.riskScore > $1.riskScore }) {
                let vc = d.vulnerabilities.count
                let pc = d.ports.filter { $0.state == .open }.count
                if vc > 0 || pc > 0 {
                    print("  \(d.ip)  \(d.host ?? "?")  os=\(d.os ?? "?")  ports=\(pc)  vulns=\(vc)  risk=\(String(format: "%.1f", d.riskScore))")
                }
            }

            if config.webhookEnabled {
                let summary = ScanSummary(timestamp: result.timestamp, duration: duration, deviceCount: scannedDevices.count,
                    totalOpenPorts: totalOpen, totalVulnerabilities: totalVulns, riskScore: avgRisk, config: config)
                await alert.sendScanComplete(scanSummary: summary, devices: scannedDevices, webhookURL: config.webhookURL)
            }

            Logger.app.notice("Headless scan complete: \(scannedDevices.count) devices in \(String(format: "%.1f", duration))s")
        } catch {
            print("Scan failed: \(error.localizedDescription)")
            Logger.app.error("Headless scan failed: \(error.localizedDescription)")
        }
    }

    private static func exportJSON(devices: [Device]) -> String {
        let out = devices.map(mapToExportDevice)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(out) else { return "[]" }
        return String(data: data, encoding: .utf8) ?? "[]"
    }
}
