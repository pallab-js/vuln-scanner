import Testing
import Foundation
import Core

@Test func diContainerResolvesRegisteredService() throws {
    let container = DIContainer()
    container.register(String.self) { _ in "test" }
    let value: String = try container.resolve()
    #expect(value == "test")
    container.reset()
}

@Test func diContainerThrowsOnUnregisteredService() {
    let container = DIContainer()
    #expect(throws: DIError.self) {
        try container.resolve() as String
    }
    container.reset()
}

@Test func loggerFormatsMetadata() {
    let log = Logger(category: .app)
    let result = log.withMetadata("test", metadata: ["key": "value"])
    #expect(result == "test | key=value")
}

// MARK: - Vuln Edge Cases
@Test func vulnWithEmptyCompliance() {
    let v = Vuln(id: "VULN-001", severity: 5, description: "test")
    #expect(v.compliance.isEmpty)
    #expect(v.cve == nil)
    #expect(v.recommendation == nil)
}

@Test func vulnWithAllFields() {
    let v = Vuln(id: "VULN-001", severity: 9.5, description: "critical",
                 recommendation: "fix it", cve: "CVE-2024-1234",
                 compliance: [.pciDSS, .hipaa])
    #expect(v.severity == 9.5)
    #expect(v.cve == "CVE-2024-1234")
    #expect(v.compliance.count == 2)
    #expect(v.complianceIDs == ["PCI-DSS", "HIPAA"])
}

@Test func vulnSortsBySeverityDescending() {
    let low = Vuln(id: "A", severity: 2, description: "low")
    let high = Vuln(id: "B", severity: 9, description: "high")
    // < is inverted: higher severity sorts first (descending)
    #expect(high < low)
    #expect(!(low < high))
    let sorted = [low, high].sorted()
    #expect(sorted == [high, low])
}

// MARK: - ComplianceFramework Cases
@Test func complianceFrameworkAllCases() {
    #expect(ComplianceFramework.allCases.count == 5)
    #expect(ComplianceFramework(rawValue: "PCI-DSS") == .pciDSS)
    #expect(ComplianceFramework(rawValue: "INVALID") == nil)
}

@Test func complianceFrameworkDisplayNames() {
    #expect(ComplianceFramework.pciDSS.displayName == "PCI-DSS")
    #expect(ComplianceFramework.gdpr.displayName == "GDPR")
}

// MARK: - NetworkError Edge Cases
@Test func networkErrorFromPOSIX() {
    let posix = POSIXError(.ECONNREFUSED)
    let err = NetworkError.from(posix)
    #expect(err.errorDescription?.contains("refused") == true)
}

@Test func networkErrorFromCancellation() {
    let err = NetworkError.from(CancellationError())
    #expect(err == .scanCancelled)
}

@Test func networkErrorFromStringHeuristics() {
    let timeout = NSError(domain: "test", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "connection timed out"])
    let mapped = NetworkError.from(timeout)
    // Should map to connectionTimeout case regardless of associated value
    if case .connectionTimeout = mapped {
        #expect(true)
    } else {
        #expect(false, "expected .connectionTimeout but got \(mapped)")
    }
}

// MARK: - SeverityLevel Bounds
@Test func severityLevelFromScore() {
    #expect(SeverityLevel.from(score: 10) == .critical)
    #expect(SeverityLevel.from(score: 7) == .high)
    #expect(SeverityLevel.from(score: 5) == .medium)
    #expect(SeverityLevel.from(score: 2) == .low)
    #expect(SeverityLevel.from(score: 0) == .info)
}

@Test func severityLevelRanges() {
    #expect(SeverityLevel.critical.range == 9.0...10.0)
    #expect(SeverityLevel.high.range == 7.0...8.9)
    #expect(SeverityLevel.info.range == 0.0...0.9)
}

// MARK: - ScanConfig Edge Cases
@Test func scanConfigDefaults() {
    let d = ScanConfig.default
    #expect(d.portRange == 1...1024)
    #expect(d.timeout == 2.0)
    #expect(d.maxConcurrency == 32)
    #expect(d.excludeIPs.isEmpty)
    #expect(!d.scanUDP)
}

@Test func scanConfigClampsValues() {
    let c = ScanConfig(portRange: 1...1024, timeout: 2, maxConcurrency: 999,
                       excludeIPs: [], serviceDetection: true, osDetection: true)
    #expect(c.maxConcurrency <= 64)
}

@Test func scanConfigScheduleClamping() {
    let c = ScanConfig(portRange: 1...1024, timeout: 2, maxConcurrency: 32,
                       excludeIPs: [], serviceDetection: true, osDetection: true,
                       scheduleIntervalHours: 999)
    #expect(c.scheduleIntervalHours <= 168)
    #expect(c.scheduleIntervalHours >= 1)
}

// MARK: - Device Risk Score Edge Cases
@Test func deviceRiskScoreEmpty() {
    let d = Device(ip: "10.0.0.1")
    #expect(d.riskScore == 0)
}

@Test func deviceRiskScoreWithPortsOnly() {
    let d = Device(ip: "10.0.0.1", ports: [ScanPort(number: 80, state: .open)])
    #expect(d.riskScore > 0)
}

@Test func deviceRiskScoreWithVulns() {
    let vulns = [Vuln(id: "VULN-001", severity: 9, description: "critical")]
    let d = Device(ip: "10.0.0.1", ports: [ScanPort(number: 22, state: .open)],
                   vulnerabilities: vulns)
    #expect(d.riskScore >= 7)
}

// MARK: - ScanPort Edge Cases
@Test func scanPortIdentification() {
    let p = ScanPort(number: 443, state: .open, service: "https")
    #expect(p.id == "443/tcp")
    #expect(p.service == "https")
}

@Test func scanPortClosed() {
    let p = ScanPort(number: 22, state: .closed)
    #expect(p.state.rawValue == "closed")
}

@Test func portStateOrdering() {
    // open < closed alphabetically in rawValue ("closed" < "filtered" < "open" < "unknown")
    let states = [PortState.open, .closed, .filtered, .unknown]
    let sorted = states.sorted()
    #expect(sorted == [.closed, .filtered, .open, .unknown])
}

// MARK: - TrendData Edge Cases
@Test func trendDataEmpty() {
    let t = TrendData(totalScans: 0, vulnsOverTime: [], devicesOverTime: [], riskOverTime: [], topCVE: [])
    #expect(t.totalScans == 0)
    #expect(t.topCVE.isEmpty)
}

// MARK: - Service Edge Cases
@Test func serviceWithNoBanner() {
    let s = Service(name: "ssh")
    #expect(s.banner == nil)
    #expect(s.version == nil)
    #expect(s.confidence == 1.0)
}

@Test func serviceOrdering() {
    let a = Service(name: "http")
    let b = Service(name: "ssh")
    #expect(a < b)
}

// MARK: - MemoryTracker
@Test func memoryTrackerReturnsValues() {
    let current = MemoryTracker.shared.currentRSSMB
    #expect(current > 0)
    #expect(current < 100000)
}

// MARK: - Tag Model
@Test func tagCreation() {
    let t = Tag(name: "production", color: "#FF0000")
    #expect(t.name == "production")
    #expect(t.id == "production")
}

@Test func tagUniqueness() {
    let a = Tag(name: "web")
    let b = Tag(name: "web")
    #expect(a == b)
}
