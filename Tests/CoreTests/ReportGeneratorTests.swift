import Testing
import Foundation
@testable import Core

@Test func reportGeneratorProducesHTML() {
    let gen = ReportGenerator()
    let device = Device(
        ip: "192.168.1.1", mac: "00:11:22:33:44:55", host: "test.local", os: "TestOS 1.0",
        ports: [
            ScanPort(number: 80, state: .open, transport: .tcp, service: "http", banner: "Apache"),
            ScanPort(number: 443, state: .open, transport: .tcp, service: "https"),
        ],
        vulnerabilities: [
            Vuln(id: "CVE-2024-0001", severity: 9.0, description: "Critical vuln", recommendation: "Patch", cve: "CVE-2024-0001", compliance: [.pciDSS]),
        ]
    )
    let config = ScanConfig.default
    let html = gen.generateHTML(devices: [device], scanDuration: 1.5, timestamp: Date(), config: config)
    #expect(html.contains("192.168.1.1"))
    #expect(html.contains("CVE-2024-0001"))
    #expect(html.contains("HTTP"))
    #expect(html.contains("Max Risk"))
}

@Test func reportGeneratorEmptyDevices() {
    let gen = ReportGenerator()
    let config = ScanConfig.default
    let html = gen.generateHTML(devices: [], scanDuration: 0, timestamp: Date(), config: config)
    #expect(html.contains("0 devices"))
}

@Test func reportGeneratorIncludesConfigDetails() {
    let gen = ReportGenerator()
    let config = ScanConfig(
        portRange: 1...1024, timeout: 2.0, maxConcurrency: 10,
        excludeIPs: [], serviceDetection: true, osDetection: true,
        apiKey: "", rulesURL: "https://example.com/rules.json"
    )
    let device = Device(ip: "10.0.0.1")
    let html = gen.generateHTML(devices: [device], scanDuration: 2, timestamp: Date(), config: config)
    #expect(html.contains("1-1024"))
    #expect(html.contains("10"))
}

@Test func exportModelsMapping() {
    let device = Device(
        ip: "192.168.1.10", mac: "aa:bb:cc:dd:ee:ff", host: "server", os: "OS",
        ports: [
            ScanPort(number: 22, state: .open, transport: .tcp, service: "ssh", banner: "OpenSSH"),
        ],
        vulnerabilities: [
            Vuln(id: "CVE-2024-0002", severity: 7.5, description: "SSH vuln", recommendation: "Update", compliance: [.hipaa]),
        ]
    )
    let exportDev = mapToExportDevice(device)
    #expect(exportDev.ip == "192.168.1.10")
    #expect(exportDev.host == "server")
    #expect(exportDev.mac == "aa:bb:cc:dd:ee:ff")
    #expect(exportDev.openPorts.count == 1)
    #expect(exportDev.openPorts[0].port == 22)
    #expect(exportDev.vulnerabilities.count == 1)
    #expect(exportDev.vulnerabilities[0].id == "CVE-2024-0002")
}

@Test func scanConfigDefaultSanity() {
    let config = ScanConfig.default
    #expect(config.portRange == 1...1024)
    #expect(config.timeout == 2.0)
    #expect(config.maxConcurrency == 32)
    #expect(config.excludeIPs.isEmpty)
    #expect(config.serviceDetection)
    #expect(config.osDetection)
}

@Test func scanResultBasicCreation() {
    let device = Device(ip: "10.0.0.1")
    let result = ScanResult(devices: [device], scanDuration: 3.0, totalPortsScanned: 1024)
    #expect(result.devices.count == 1)
    #expect(result.scanDuration == 3.0)
    #expect(result.totalPortsScanned == 1024)
}
