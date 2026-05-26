import Foundation
import Core

public struct BonjourDiscovery {
    private let logger = Logger(category: .discovery)

    public init() {}

    public func discoverServices(timeout: TimeInterval = 5.0) -> AsyncStream<BonjourService> {
        AsyncStream { continuation in
            let scanner = BonjourScanner(timeout: timeout) { services in
                for service in services {
                    continuation.yield(service)
                }
                continuation.finish()
            }
            scanner.start()
        }
    }
}

public struct BonjourService: Sendable, Identifiable {
    public let id: String
    public let name: String
    public let type: String
    public let domain: String
    public let ip: String?
    public let port: Int

    public init(name: String, type: String, domain: String, ip: String?, port: Int) {
        self.id = "\(name).\(type)"
        self.name = name
        self.type = type
        self.domain = domain
        self.ip = ip
        self.port = port
    }
}

private final class BonjourScanner: NSObject, @unchecked Sendable {
    private let timeout: TimeInterval
    private let completion: ([BonjourService]) -> Void
    private var browsers: [NetServiceBrowser] = []
    private var services: [BonjourService] = []
    private let delegate = BonjourScanDelegate()

    private let serviceTypes = ["_http._tcp", "_ssh._tcp", "_smb._tcp",
                                "_printer._tcp", "_ipp._tcp", "_afpovertcp._tcp"]

    init(timeout: TimeInterval, completion: @escaping ([BonjourService]) -> Void) {
        self.timeout = timeout
        self.completion = completion
    }

    func start() {
        delegate.onResolved = { [weak self] service in
            self?.services.append(service)
        }

        for type in serviceTypes {
            let browser = NetServiceBrowser()
            browser.delegate = delegate
            browser.schedule(in: .main, forMode: .common)
            browser.searchForServices(ofType: type, inDomain: "local.")
            browsers.append(browser)
        }

        DispatchQueue.main.asyncAfter(deadline: .now() + timeout) { [weak self] in
            guard let self = self else { return }
            self.browsers.forEach { $0.stop() }
            self.completion(self.services)
        }
    }
}

private final class BonjourScanDelegate: NSObject, NetServiceBrowserDelegate, NetServiceDelegate {
    var onResolved: ((BonjourService) -> Void)?

    func netServiceBrowser(_ browser: NetServiceBrowser, didFind service: NetService, moreComing: Bool) {
        service.delegate = self
        service.resolve(withTimeout: 5.0)
    }

    func netServiceDidResolveAddress(_ sender: NetService) {
        let bonjour = BonjourService(
            name: sender.name,
            type: sender.type,
            domain: sender.domain,
            ip: sender.hostName,
            port: sender.port
        )
        onResolved?(bonjour)
        Logger.discovery.debug("Bonjour found: \(sender.name) (\(sender.type))")
    }
}
