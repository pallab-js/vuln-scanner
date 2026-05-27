import Foundation

public struct DeliveryConfig: Codable, Sendable {
    public var emailEnabled: Bool
    public var smtpHost: String
    public var smtpPort: Int
    public var smtpUser: String
    public var smtpPassword: String
    public var emailRecipients: [String]
    public var slackWebhook: String
    public var slackChannel: String
    public var format: ReportFormat

    public static let `default` = DeliveryConfig(
        emailEnabled: false, smtpHost: "", smtpPort: 587, smtpUser: "", smtpPassword: "",
        emailRecipients: [], slackWebhook: "", slackChannel: "", format: .html
    )
}

public enum ReportFormat: String, Codable, Sendable, CaseIterable {
    case html = "HTML"
    case pdf = "PDF"
    case csv = "CSV"
    case json = "JSON"
}

public enum DeliveryError: Error, LocalizedError, Sendable {
    case notConfigured
    case sendFailed(String)

    public var errorDescription: String? {
        switch self {
        case .notConfigured: return "Report delivery not configured"
        case .sendFailed(let msg): return "Delivery failed: \(msg)"
        }
    }
}

public final class ReportDelivery: @unchecked Sendable {
    public static let shared = ReportDelivery()
    public var config: DeliveryConfig {
        get { loadConfig() }
        set { saveConfig(newValue) }
    }

    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    private var configURL: URL? {
        guard let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else { return nil }
        let appDir = dir.appendingPathComponent("com.lanscanner")
        try? FileManager.default.createDirectory(at: appDir, withIntermediateDirectories: true)
        return appDir.appendingPathComponent("delivery.json")
    }

    public func send(report: String, format: ReportFormat, title: String) async -> DeliveryError? {
        let c = config
        if !c.slackWebhook.isEmpty {
            return await sendSlack(report: report, format: format, title: title, webhook: c.slackWebhook)
        }
        if c.emailEnabled && !c.smtpHost.isEmpty {
            return await sendEmail(report: report, format: format, title: title)
        }
        return .notConfigured
    }

    private func sendSlack(report: String, format: ReportFormat, title: String, webhook: String) async -> DeliveryError? {
        guard let url = URL(string: webhook) else { return .sendFailed("Invalid webhook URL") }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let payload: [String: Any] = [
            "text": "\(title)\n```\(report.prefix(3000))```",
            "username": "LAN Scanner"
        ]
        request.httpBody = try? JSONSerialization.data(withJSONObject: payload)
        do {
            let (_, response) = try await URLSession.shared.data(for: request)
            if let http = response as? HTTPURLResponse, http.statusCode >= 400 {
                return .sendFailed("Slack returned \(http.statusCode)")
            }
            return nil
        } catch {
            return .sendFailed(error.localizedDescription)
        }
    }

    private func sendEmail(report: String, format: ReportFormat, title: String) async -> DeliveryError? {
        return .sendFailed("Email delivery requires SMTP configuration")
    }

    private func loadConfig() -> DeliveryConfig {
        guard let url = configURL, let data = try? Data(contentsOf: url),
              let c = try? decoder.decode(DeliveryConfig.self, from: data) else { return .default }
        return c
    }

    private func saveConfig(_ c: DeliveryConfig) {
        guard let url = configURL, let data = try? encoder.encode(c) else { return }
        try? data.write(to: url, options: .atomic)
    }
}
