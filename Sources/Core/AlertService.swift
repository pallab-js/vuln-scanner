import Foundation

private struct WebhookPayload: Codable, Sendable {
    let attachments: [WebhookAttachment]
}

private struct WebhookAttachment: Codable, Sendable {
    let color: String
    let title: String
    let fields: [WebhookField]
    let footer: String
    let ts: Int
}

private struct WebhookField: Codable, Sendable {
    let title: String
    let value: String
    let short: Bool
}

public struct AlertService: Sendable {
    private let session = URLSession.shared

    public init() {}

    public func sendScanComplete(scanSummary: ScanSummary, devices: [Device], webhookURL: String) async {
        guard !webhookURL.trimmingCharacters(in: .whitespaces).isEmpty,
              let url = URL(string: webhookURL) else { return }

        let criticalCount = devices.reduce(0) { $0 + $1.vulnerabilities.filter { $0.severity >= 9 }.count }
        let highCount = devices.reduce(0) { $0 + $1.vulnerabilities.filter { $0.severity >= 7 && $0.severity < 9 }.count }

        let color: String = criticalCount > 0 ? "danger" : highCount > 0 ? "warning" : "good"

        let payload = WebhookPayload(
            attachments: [
                WebhookAttachment(
                    color: color,
                    title: "LAN Scanner \u{2014} Scan Complete",
                    fields: [
                        WebhookField(title: "Devices", value: "\(scanSummary.deviceCount)", short: true),
                        WebhookField(title: "Open Ports", value: "\(scanSummary.totalOpenPorts)", short: true),
                        WebhookField(title: "Vulnerabilities", value: "\(scanSummary.totalVulnerabilities)", short: true),
                        WebhookField(title: "Risk Score", value: String(format: "%.1f", scanSummary.riskScore), short: true),
                        WebhookField(title: "Critical", value: "\(criticalCount)", short: true),
                        WebhookField(title: "High", value: "\(highCount)", short: true),
                    ],
                    footer: "LANScanner",
                    ts: Int(scanSummary.timestamp.timeIntervalSince1970)
                )
            ]
        )

        guard let body = try? JSONEncoder().encode(payload) else { return }

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
