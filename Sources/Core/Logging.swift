import OSLog
import Foundation

public enum LogCategory: String, CaseIterable, Sendable {
    case app = "App"
    case lifecycle = "Lifecycle"
    case discovery = "Discovery"
    case scanning = "Scanning"
    case mapping = "Mapping"
    case network = "Network"
    case ui = "UI"
    case config = "Config"

    var osLog: OSLog {
        OSLog(subsystem: subsystem, category: rawValue)
    }

    private var subsystem: String {
        Bundle.main.bundleIdentifier ?? "com.lanscanner"
    }
}

public struct Logger: Sendable {
    private let category: LogCategory

    public init(category: LogCategory) {
        self.category = category
    }

    public func debug(_ message: String) {
        os_log(.debug, log: category.osLog, "%{public}@", message)
    }

    public func info(_ message: String) {
        os_log(.info, log: category.osLog, "%{public}@", message)
    }

    public func notice(_ message: String) {
        os_log(.default, log: category.osLog, "%{public}@", message)
    }

    public func error(_ message: String) {
        os_log(.error, log: category.osLog, "%{public}@", message)
    }

    public func fault(_ message: String) {
        os_log(.fault, log: category.osLog, "%{public}@", message)
    }

    public func withMetadata(_ message: String, metadata: [String: Sendable]) -> String {
        let metaString = metadata.map { "\($0.key)=\($0.value)" }.joined(separator: ", ")
        return "\(message) | \(metaString)"
    }
}

public extension Logger {
    static let app = Logger(category: .app)
    static let lifecycle = Logger(category: .lifecycle)
    static let discovery = Logger(category: .discovery)
    static let scanning = Logger(category: .scanning)
    static let mapping = Logger(category: .mapping)
    static let network = Logger(category: .network)
    static let ui = Logger(category: .ui)
    static let config = Logger(category: .config)
}
