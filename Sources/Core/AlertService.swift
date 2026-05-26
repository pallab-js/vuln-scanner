import Foundation

public struct AlertService: Sendable {
    private let session = URLSession.shared

    public init() {}

    public func sendScanComplete(scanSummary: ScanSummary, devices: [Device], webhookURL: String) async {
        guard !webhookURL.trimmingCharacters(in: .whitespaces).isEmpty,
              let url = URL(string: webhookURL) else { return }

        let criticalCount = devices.reduce(0) { $0 + $1.vulnerabilities.filter { $0.severity >= 9 }.count }
        let highCount = devices.reduce(0) { $0 + $1.vulnerabilities.filter { $0.severity >= 7 && $0.severity < 9 }.count }

        let color: String = criticalCount > 0 ? "danger" : highCount > 0 ? "warning" : "good"

        let payload: [String: Any] = [
            "attachments": [[
                "color": color,
                "title": "LAN Scanner — Scan Complete",
                "fields": [
                    ["title": "Devices", "value": "\(scanSummary.deviceCount)", "short": true],
                    ["title": "Open Ports", "value": "\(scanSummary.totalOpenPorts)", "short": true],
                    ["title": "Vulnerabilities", "value": "\(scanSummary.totalVulnerabilities)", "short": true],
                    ["title": "Risk Score", "value": String(format: "%.1f", scanSummary.riskScore), "short": true],
                    ["title": "Critical", "value": "\(criticalCount)", "short": true],
                    ["title": "High", "value": "\(highCount)", "short": true],
                ],
                "footer": "LANScanner",
                "ts": Int(scanSummary.timestamp.timeIntervalSince1970)
            ]]
        ]

        guard let body = try? JSONSerialization.data(withJSONObject: payload, options: []) else { return }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = body

        do {
            let (_, response) = try await session.data(for: request)
            if let httpResponse = response as? HTTPURLResponse {
                Logger.network.notice("Webhook sent: \(httpResponse.statusCode)")
            }
        } catch {
            Logger.network.error("Webhook failed: \(error.localizedDescription)")
        }
    }
}
