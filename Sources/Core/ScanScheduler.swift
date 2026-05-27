import Foundation

/// Manages in-app timers for periodic scans and installs/uninstalls launchd agents.
/// @unchecked Sendable required because DispatchSourceTimer is not Sendable,
/// but all mutable state is accessed from the serial queue.
public final class ScanScheduler: @unchecked Sendable {
    public static let shared = ScanScheduler()
    public private(set) var isScheduled = false
    public private(set) var nextScanAt: Date?

    private var timer: DispatchSourceTimer?
    private var scanAction: (@Sendable () async -> Void)?

    private init() {}

    public func configure(action: @escaping @Sendable () async -> Void) {
        scanAction = action
    }

    public func schedule(intervalHours: Double) {
        guard intervalHours >= 1 else { return }
        cancel()

        let intervalSeconds = Int(intervalHours * 3600)
        let timer = DispatchSource.makeTimerSource(queue: .global())
        timer.schedule(deadline: .now() + .seconds(intervalSeconds), repeating: .seconds(intervalSeconds), leeway: .seconds(300))
        timer.setEventHandler { [weak self] in
            guard let self = self, let action = self.scanAction else { return }
            self.nextScanAt = Date().addingTimeInterval(intervalHours * 3600)
            Task { await action() }
        }
        timer.resume()
        self.timer = timer
        isScheduled = true
        nextScanAt = Date().addingTimeInterval(intervalHours * 3600)
        Logger.config.notice("Scanner scheduled every \(intervalHours)h")
    }

    public func cancel() {
        timer?.cancel()
        timer = nil
        isScheduled = false
        nextScanAt = nil
    }

    public static func installLaunchAgent(label: String = "com.lanscanner.scheduler", path: String, intervalSeconds: Int) -> Bool {
        let plist: [String: Any] = [
            "Label": label,
            "ProgramArguments": [path, "--scheduled-scan"],
            "StartInterval": intervalSeconds,
            "RunAtLoad": false,
            "KeepAlive": false,
            "StandardOutPath": "/tmp/lanscanner-scheduler.stdout",
            "StandardErrorPath": "/tmp/lanscanner-scheduler.stderr"
        ]

        guard let data = try? PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0) else {
            return false
        }

        let agentDir = URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/LaunchAgents")
        try? FileManager.default.createDirectory(at: agentDir, withIntermediateDirectories: true)
        let agentPath = agentDir.appendingPathComponent("\(label).plist")

        do {
            try data.write(to: agentPath, options: .atomic)
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
            process.arguments = ["load", agentPath.path]
            try process.run()
            process.waitUntilExit()
            return process.terminationStatus == 0
        } catch {
            Logger.config.error("Failed to install launch agent: \(error.localizedDescription)")
            return false
        }
    }

    public static func uninstallLaunchAgent(label: String = "com.lanscanner.scheduler") -> Bool {
        let agentPath = URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/LaunchAgents/\(label).plist")
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["unload", agentPath.path]
        try? process.run()
        process.waitUntilExit()
        try? FileManager.default.removeItem(at: agentPath)
        return true
    }
}
