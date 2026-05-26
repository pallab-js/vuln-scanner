import Foundation

public struct ReportGenerator: Sendable {
    public init() {}

    public func generateHTML(devices: [Device], scanDuration: TimeInterval, timestamp: Date, config: ScanConfig) -> String {
        let totalDevices = devices.count
        let totalOpen = devices.reduce(0) { $0 + $1.ports.filter { $0.state == .open }.count }
        let totalVulns = devices.reduce(0) { $0 + $1.vulnerabilities.count }
        let avgRisk = totalDevices > 0 ? devices.reduce(0.0) { $0 + $1.riskScore } / Double(totalDevices) : 0
        let critical = devices.reduce(0) { $0 + $1.vulnerabilities.filter { $0.severity >= 9 }.count }
        let high = devices.reduce(0) { $0 + $1.vulnerabilities.filter { $0.severity >= 7 && $0.severity < 9 }.count }
        let medium = devices.reduce(0) { $0 + $1.vulnerabilities.filter { $0.severity >= 4 && $0.severity < 7 }.count }
        let low = devices.reduce(0) { $0 + $1.vulnerabilities.filter { $0.severity >= 1 && $0.severity < 4 }.count }

        let dateStr = timestamp.formatted(date: .long, time: .standard)
        let rangeStr = config.portRange.lowerBound == 1 && config.portRange.upperBound == 1024
            ? "Well-known (1-1024)" : "\(config.portRange.lowerBound)-\(config.portRange.upperBound)"

        let deviceRows = devices.sorted { $0.riskScore > $1.riskScore }.map { deviceRow($0) }.joined()
        let vulnRows = devices.flatMap(\.vulnerabilities).sorted().prefix(50).map { vulnRow($0) }.joined()

        return """
        <!DOCTYPE html>
        <html lang="en">
        <head>
        <meta charset="UTF-8">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { font-family: -apple-system, Helvetica, Arial, sans-serif; font-size: 11pt; color: #1a1a1a; background: #fff; padding: 40px; max-width: 900px; margin: auto; }
            h1 { font-size: 24pt; font-weight: 700; margin-bottom: 4px; }
            h2 { font-size: 16pt; font-weight: 600; margin: 24px 0 12px; border-bottom: 2px solid #eee; padding-bottom: 4px; }
            h3 { font-size: 13pt; font-weight: 600; margin: 16px 0 8px; }
            .subtitle { color: #666; font-size: 10pt; margin-bottom: 24px; }
            .summary-grid { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 24px; }
            .card { flex: 1; min-width: 120px; padding: 16px; border-radius: 8px; border: 1px solid #e0e0e0; text-align: center; }
            .card .value { font-size: 22pt; font-weight: 700; }
            .card .label { font-size: 8pt; color: #666; text-transform: uppercase; letter-spacing: 0.5px; }
            .card.critical .value { color: #d32f2f; }
            .card.high .value { color: #f57c00; }
            .card.medium .value { color: #fbc02d; }
            .card.low .value { color: #1976d2; }
            .bar-container { display: flex; height: 24px; border-radius: 4px; overflow: hidden; margin: 12px 0; }
            .bar-segment { display: flex; align-items: center; justify-content: center; font-size: 8pt; font-weight: 600; color: #fff; }
            table { width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 9pt; }
            th { background: #f5f5f5; text-align: left; padding: 8px; font-weight: 600; border-bottom: 2px solid #e0e0e0; }
            td { padding: 8px; border-bottom: 1px solid #eee; }
            .risk-badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 8pt; font-weight: 600; color: #fff; }
            .risk-7 { background: #d32f2f; }
            .risk-4 { background: #f57c00; }
            .risk-1 { background: #fbc02d; color: #333; }
            .risk-0 { background: #388e3c; }
            .footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid #eee; font-size: 8pt; color: #999; }
            .config-info { font-size: 9pt; color: #666; margin-bottom: 20px; }
            .rec { padding: 8px 12px; margin: 4px 0; border-left: 3px solid #1976d2; background: #f8f9fa; font-size: 9pt; border-radius: 0 4px 4px 0; }
            @media print { body { padding: 20px; } .card { break-inside: avoid; } }
        </style>
        </head>
        <body>
        <h1>LAN Security Scan Report</h1>
        <p class="subtitle">Generated \(dateStr) · Port range \(rangeStr)\(config.scanUDP ? " + UDP" : "") · \(config.timeout)s timeout</p>

        <h2>Executive Summary</h2>
        <div class="summary-grid">
            <div class="card"><div class="value">\(totalDevices)</div><div class="label">Devices</div></div>
            <div class="card"><div class="value">\(totalOpen)</div><div class="label">Open Ports</div></div>
            <div class="card \(critical > 0 ? "critical" : "")"><div class="value">\(critical)</div><div class="label">Critical</div></div>
            <div class="card \(high > 0 ? "high" : "")"><div class="value">\(high)</div><div class="label">High</div></div>
            <div class="card \(medium > 0 ? "medium" : "")"><div class="value">\(medium)</div><div class="label">Medium</div></div>
            <div class="card \(low > 0 ? "low" : "")"><div class="value">\(low)</div><div class="label">Low</div></div>
            <div class="card"><div class="value">\(String(format: "%.1f", avgRisk))</div><div class="label">Risk Score</div></div>
            <div class="card"><div class="value">\(String(format: "%.1fs", scanDuration))</div><div class="label">Duration</div></div>
        </div>

        \(severityBar(critical: critical, high: high, medium: medium, low: low, total: totalVulns))

        <h2>Device Inventory (\(totalDevices))</h2>
        <table><thead><tr>
            <th>IP</th><th>Hostname</th><th>OS</th><th>MAC</th><th>Ports</th><th>Vulns</th><th>Risk</th>
        </tr></thead><tbody>
        \(deviceRows)
        </tbody></table>

        <h2>Vulnerability Details</h2>
        \(vulnRows.isEmpty ? "<p style='color: #666;'>No vulnerabilities detected.</p>" : vulnRows)

        <h2>Compliance Mapping</h2>
        \(complianceSection(devices: devices))

        <h2>Recommendations</h2>
        \(recommendations(devices: devices))

        <p class="footer">LAN Scanner · Report generated \(dateStr) · \(totalDevices) devices scanned in \(String(format: "%.1f", scanDuration))s</p>
        </body></html>
        """
    }

    private func severityBar(critical: Int, high: Int, medium: Int, low: Int, total: Int) -> String {
        guard total > 0 else { return "" }
        let pct = { (val: Int) in Double(val) / Double(max(total, 1)) * 100 }
        let segments = [
            (pct(critical), "#d32f2f", "\(critical)"),
            (pct(high), "#f57c00", "\(high)"),
            (pct(medium), "#fbc02d", "\(medium)"),
            (pct(low), "#1976d2", "\(low)"),
        ]
        let bars = segments.filter { $0.0 > 0 }.map { "<div class=\"bar-segment\" style=\"width: \(String(format: "%.1f", $0.0))%; background: \($0.1);\">\($0.2)</div>" }.joined()
        return """
        <h3>Severity Distribution</h3>
        <div class="bar-container">\(bars)</div>
        """
    }

    private func deviceRow(_ device: Device) -> String {
        let openCount = device.ports.filter { $0.state == .open }.count
        let riskClass: String
        switch device.riskScore {
        case 7...: riskClass = "risk-7"
        case 4...: riskClass = "risk-4"
        case 1...: riskClass = "risk-1"
        default: riskClass = "risk-0"
        }
        return """
        <tr>
            <td>\(device.ip)</td>
            <td>\(device.host ?? "—")</td>
            <td>\(device.os ?? "—")</td>
            <td>\(device.mac ?? "—")</td>
            <td>\(openCount)</td>
            <td>\(device.vulnerabilities.count)</td>
            <td><span class="risk-badge \(riskClass)">\(String(format: "%.1f", device.riskScore))</span></td>
        </tr>
        """
    }

    private func vulnRow(_ vuln: Vuln) -> String {
        let color: String
        switch vuln.severity {
        case 9...: color = "#d32f2f"
        case 7...: color = "#f57c00"
        case 4...: color = "#fbc02d"
        case 1...: color = "#1976d2"
        default: color = "#9e9e9e"
        }
        let cveStr = vuln.cve.map { " <span style='background: #e3f2fd; padding: 1px 6px; border-radius: 3px; font-size: 8pt;'>\($0)</span>" } ?? ""
        let compStr = vuln.compliance.isEmpty ? "" : vuln.compliance.map { "<span style='display:inline-block;font-size:7pt;font-weight:600;padding:1px 5px;border-radius:3px;margin-right:3px;background:\(frameworkCSS($0));color:#fff;'>\($0.rawValue)</span>" }.joined()
        let recStr = vuln.recommendation.map { "<div class=\"rec\">💡 \($0)</div>" } ?? ""
        return """
        <div style="padding: 8px 0; border-bottom: 1px solid #eee;">
            <div style="display: flex; align-items: center; gap: 8px;">
                <span style="background: \(color); color: #fff; padding: 2px 8px; border-radius: 10px; font-size: 8pt; font-weight: 600;">\(String(format: "%.1f", vuln.severity))</span>
                <span style="font-weight: 600; font-size: 10pt;">\(vuln.id)</span>\(cveStr)
            </div>
            <div style="margin: 4px 0;">\(compStr)</div>
            <p style="margin: 4px 0; font-size: 9pt; color: #333;">\(vuln.description)</p>
            \(recStr)
        </div>
        """
    }

    private func frameworkCSS(_ fw: ComplianceFramework) -> String {
        switch fw {
        case .pciDSS: return "#d32f2f"
        case .hipaa: return "#1976d2"
        case .gdpr: return "#7b1fa2"
        case .soc2: return "#388e3c"
        case .nist: return "#f57c00"
        }
    }

    private func recommendations(devices: [Device]) -> String {
        var items: [String] = []
        let criticalDevices = devices.filter { $0.vulnerabilities.contains(where: { $0.severity >= 9 }) }
        if !criticalDevices.isEmpty {
            items.append("Address critical vulnerabilities on \(criticalDevices.map(\.ip).joined(separator: ", ")) immediately.")
        }
        let openSMB = devices.filter { $0.ports.contains(where: { $0.number == 445 && $0.state == .open }) }
        if !openSMB.isEmpty {
            items.append("Disable SMB (port 445) on non-essential systems to reduce attack surface.")
        }
        let openRDP = devices.filter { $0.ports.contains(where: { $0.number == 3389 && $0.state == .open }) }
        if !openRDP.isEmpty {
            items.append("Restrict RDP (port 3389) access with VPN or firewall rules.")
        }
        if items.isEmpty {
            items.append("No critical recommendations. Maintain regular scan cadence and keep systems updated.")
        }
        return items.map { "<div class=\"rec\">\($0)</div>" }.joined()
    }

    private func complianceSection(devices: [Device]) -> String {
        let frameworks = ComplianceFramework.allCases
        var rows = ""
        for fw in frameworks {
            let related = devices.flatMap(\.vulnerabilities).filter { $0.compliance.contains(fw) }
            let unique = Set(related.map(\.id)).sorted()
            guard !unique.isEmpty else { continue }
            let color = frameworkCSS(fw)
            rows += """
            <div style="margin: 8px 0; padding: 8px 12px; border-left: 3px solid \(color);">
                <strong style="color: \(color);">\(fw.rawValue)</strong> — \(related.count) findings across \(unique.count) rule types
                <div style="font-size: 8pt; color: #666; margin-top: 4px;">\(unique.joined(separator: ", "))</div>
            </div>
            """
        }
        return rows.isEmpty ? "<p style='color: #666;'>No compliance mappings in detected vulnerabilities.</p>" : rows
    }
}
