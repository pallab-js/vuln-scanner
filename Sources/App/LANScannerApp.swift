import SwiftUI
import Core
import UI

@main
struct LANScannerApp: App {
    init() {
        registerServices()
        Logger.lifecycle.notice("LANScanner starting")
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .frame(minWidth: 800, minHeight: 600)
        }
        .windowResizability(.contentMinSize)
        .commands {
            CommandGroup(replacing: .appInfo) {
                Button("About LAN Scanner") {
                    Logger.app.info("About menu selected")
                }
            }
        }
    }

    private func registerServices() {
        let container = DIContainer.shared
        container.registerSingleton(AppState.self) { _ in
            AppState()
        }
        Logger.lifecycle.debug("Services registered")
    }
}
