import Foundation

public struct AppConfig: Codable, Sendable {
    public var scan: ScanConfig
    public var logging: LogConfig
    public var excludedIPs: [String]

    public static let `default` = AppConfig(
        scan: .default,
        logging: LogConfig(level: "info", categories: nil),
        excludedIPs: []
    )

    public init(scan: ScanConfig, logging: LogConfig, excludedIPs: [String]) {
        self.scan = scan
        self.logging = logging
        self.excludedIPs = excludedIPs
    }
}

public struct LogConfig: Codable, Sendable {
    public var level: String
    public var categories: [String]?
}

public enum ConfigLoader {
    public static func load(from url: URL? = nil) -> AppConfig {
        let configURL = url ?? defaultConfigURL()
        guard let url = configURL else { return .default }

        do {
            let data = try Data(contentsOf: url)
            let decoder = JSONDecoder()
            var config = try decoder.decode(AppConfig.self, from: data)
            if config.scan.maxConcurrency > 64 {
                config.scan.maxConcurrency = 64
            }
            Logger.config.info("Config loaded from \(url.path)")
            return config
        } catch {
            Logger.config.notice("Using default config (\(error.localizedDescription))")
            return .default
        }
    }

    private static func defaultConfigURL() -> URL? {
        let paths = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)
        guard let supportDir = paths.first else { return nil }
        let appDir = supportDir.appendingPathComponent("LANScanner")
        try? FileManager.default.createDirectory(at: appDir, withIntermediateDirectories: true)
        return appDir.appendingPathComponent("config.json")
    }
}
