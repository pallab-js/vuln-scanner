import Foundation
import Observation
import Core

@Observable
public final class AppState {
    public var isReady: Bool = false
    public var statusMessage: String = "Initializing..."
    public var isScanning: Bool = false

    public init() {
        Logger.app.notice("AppState initialized")
    }

    public func updateStatus(_ message: String) {
        statusMessage = message
        Logger.app.debug("Status: \(message)")
    }
}
