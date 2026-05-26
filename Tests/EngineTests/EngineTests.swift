import Testing
import Foundation
import Core
@testable import Engine

@Test func engineModuleExists() {
    #expect(true)
}

// MARK: - VulnRules Empty Fallback
@Test func ruleLoaderEmptyRulesFallback() {
    let empty = VulnRules(version: 0, weakProtocols: [], outdatedVersions: [],
                          weakCiphers: [], eolSystems: [], dangerousPorts: [])
    #expect(empty.allRules.isEmpty)
    #expect(empty.version == 0)
}

// MARK: - VulnRule Creation
@Test func vulnRuleWithAllFields() {
    let rule = VulnRule(id: "VULN-TEST-001", severity: 7.5, description: "test",
                        recommendation: "fix", service: "ssh", pattern: "OpenSSH_[0-6]",
                        port: nil, compliance: ["PCI-DSS", "NIST"])
    #expect(rule.id == "VULN-TEST-001")
    #expect(rule.severity == 7.5)
    #expect(rule.compliance?.count == 2)
}

@Test func vulnRuleMinimal() {
    let rule = VulnRule(id: "VULN-MIN", severity: 5, description: "minimal",
                        recommendation: nil, service: nil, pattern: nil, port: nil,
                        compliance: nil)
    #expect(rule.recommendation == nil)
    #expect(rule.pattern == nil)
    #expect(rule.compliance == nil)
}

// MARK: - VulnMapper Edge Cases
@Test func vulnMapperHandlesEmptyDevice() {
    let mapper = VulnMapper()
    let device = Device(ip: "10.0.0.1")
    let vulns = mapper.map(device: device)
    #expect(vulns.isEmpty)
}

@Test func vulnMapperHandlesDeviceWithNoVulnerabilities() {
    let mapper = VulnMapper()
    let port = ScanPort(number: 8080, state: .open, service: "custom")
    let device = Device(ip: "10.0.0.1", ports: [port])
    let vulns = mapper.map(device: device)
    #expect(vulns.isEmpty)
}

@Test func vulnMapperMapsDangerousPort() {
    let mapper = VulnMapper()
    let port = ScanPort(number: 23, state: .open, service: "telnet")
    let device = Device(ip: "10.0.0.1", ports: [port])
    let vulns = mapper.map(device: device)
    let telnetVulns = vulns.filter { $0.id == "VULN-TELNET-001" }
    #expect(telnetVulns.count == 1)
    #expect(telnetVulns[0].severity == 8.5)
}

@Test func vulnMapperIgnoresClosedPorts() {
    let mapper = VulnMapper()
    let port = ScanPort(number: 23, state: .closed)
    let device = Device(ip: "10.0.0.1", ports: [port])
    let vulns = mapper.map(device: device)
    #expect(vulns.isEmpty)
}

@Test func vulnMapperBannerRegexMatching() {
    let mapper = VulnMapper()
    let port = ScanPort(number: 22, state: .open, service: "ssh",
                        banner: "SSH-2.0-OpenSSH_7.2")
    let device = Device(ip: "10.0.0.1", ports: [port])
    let vulns = mapper.map(device: device)
    let sshVulns = vulns.filter { $0.id == "VULN-SSH-001" }
    #expect(sshVulns.count == 1)
}

@Test func vulnMapperBannerNoMatch() {
    let mapper = VulnMapper()
    let port = ScanPort(number: 22, state: .open, service: "ssh",
                        banner: "SSH-2.0-OpenSSH_8.9")
    let device = Device(ip: "10.0.0.1", ports: [port])
    let vulns = mapper.map(device: device)
    let sshVulns = vulns.filter { $0.id == "VULN-SSH-001" }
    #expect(sshVulns.isEmpty)
}

@Test func vulnMapperEOLOSDetection() {
    let mapper = VulnMapper()
    let device = Device(ip: "10.0.0.1", os: "Windows 7")
    let vulns = mapper.map(device: device)
    let osVulns = vulns.filter { $0.id == "VULN-OS-001" }
    #expect(osVulns.count == 1)
}

@Test func vulnMapperModernOS() {
    let mapper = VulnMapper()
    let device = Device(ip: "10.0.0.1", os: "macOS 14")
    let vulns = mapper.map(device: device)
    let osVulns = vulns.filter { $0.id == "VULN-OS-002" }
    #expect(osVulns.isEmpty)
}

// MARK: - CustomRule Edge Cases
@Test func customRuleMinimal() {
    let r = CustomRule(id: "CUSTOM-001", category: .dangerousPort, severity: 3,
                       description: "test", recommendation: "", port: 9000)
    #expect(r.port == 9000)
    #expect(r.service == nil)
    #expect(r.compliance.isEmpty)
}

@Test func customRuleSerializationRoundTrip() throws {
    let original = CustomRule(id: "CUSTOM-001", category: .outdatedVersion,
                              severity: 7, description: "old", recommendation: "upgrade",
                              service: "nginx", pattern: "nginx/1\\.", compliance: ["PCI-DSS"])
    let data = try JSONEncoder().encode(original)
    let decoded = try JSONDecoder().decode(CustomRule.self, from: data)
    #expect(decoded.id == original.id)
    #expect(decoded.severity == original.severity)
    #expect(decoded.compliance == original.compliance)
}

@Test func customRuleCategoryImage() {
    #expect(RuleCategory.dangerousPort.systemImage == "door.left.hand.open")
    #expect(RuleCategory.eolSystem.systemImage == "desktopcomputer.trianglebadge.exclamationmark")
}

// MARK: - CustomRulesStore Edge Cases
@Test func customRulesStoreEmpty() {
    let store = CustomRulesStore.shared
    let empty = store.load()
    #expect(empty.isEmpty)
}

// MARK: - OS Fingerprinting
@Test func osFingerprinterEmptyPorts() {
    let result = OSFingerprinter().infer(ports: [])
    #expect(result == nil)
}

@Test func osFingerprinterWindowsPorts() {
    let ports = [ScanPort(number: 3389, state: .open, service: "ms-wbt-server")]
    let result = OSFingerprinter().infer(ports: ports)
    #expect(result?.lowercased().contains("windows") == true)
}

@Test func osFingerprinterMacOSPorts() {
    let ports = [ScanPort(number: 5353, state: .open, service: "mdns")]
    let result = OSFingerprinter().infer(ports: ports)
    #expect(result?.lowercased().contains("mac") == true)
}

@Test func osFingerprinterSSHBanner() {
    let ports = [ScanPort(number: 22, state: .open, service: "ssh",
                          banner: "SSH-2.0-OpenSSH_8.9 Ubuntu")]
    let result = OSFingerprinter().infer(ports: ports)
    #expect(result?.lowercased().contains("linux") == true)
}

@Test func osFingerprinterHTTPBanner() {
    let ports = [ScanPort(number: 80, state: .open, service: "http",
                          banner: "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\n")]
    let result = OSFingerprinter().infer(ports: ports)
    #expect(result?.lowercased().contains("windows") == true)
}



// MARK: - RuleLoader Bundled
@Test func ruleLoaderBundledRulesExist() {
    let rules = RuleLoader.load()
    #expect(rules.version >= 2)
    #expect(!rules.allRules.isEmpty)
    #expect(!rules.dangerousPorts.isEmpty)
    #expect(!rules.weakProtocols.isEmpty)
}

// MARK: - Vuln Compliance Passthrough
@Test func vulnMapperCompliancePassthrough() {
    let mapper = VulnMapper()
    let port = ScanPort(number: 21, state: .open, service: "ftp")
    let device = Device(ip: "10.0.0.1", ports: [port])
    let vulns = mapper.map(device: device)
    let ftpVulns = vulns.filter { $0.id == "VULN-FTP-001" }
    #expect(ftpVulns.count == 1)
    #expect(!ftpVulns[0].compliance.isEmpty)
    #expect(ftpVulns[0].compliance.contains(.pciDSS))
}

// MARK: - Vuln Uniquing
@Test func vulnMapperDeduplicates() {
    let mapper = VulnMapper()
    let port = ScanPort(number: 22, state: .open, service: "ssh",
                        banner: "SSH-2.0-OpenSSH_7.2")
    let device = Device(ip: "10.0.0.1", ports: [port, port])
    let vulns = mapper.map(device: device)
    let ids = vulns.map(\.id)
    #expect(ids.count == Set(ids).count)
}
