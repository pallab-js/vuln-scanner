import Foundation
import os

public enum DIError: Error, LocalizedError, Sendable {
    case notRegistered(String)
    case circularDependency(String)

    public var errorDescription: String? {
        switch self {
        case .notRegistered(let key):
            return "No service registered for key: \(key)"
        case .circularDependency(let key):
            return "Circular dependency detected for: \(key)"
        }
    }
}

public protocol ServiceFactory: Sendable {
    associatedtype Service
    func create(_ container: DIContainer) throws -> Service
}

public struct ClosureFactory<T>: ServiceFactory {
    public typealias Service = T
    private let closure: @Sendable (DIContainer) throws -> T

    public init(_ closure: @escaping @Sendable (DIContainer) throws -> T) {
        self.closure = closure
    }

    public func create(_ container: DIContainer) throws -> T {
        try closure(container)
    }
}

public final class DIContainer: @unchecked Sendable {
    private var factories: [String: @Sendable (DIContainer) throws -> Any] = [:]
    private var singletons: [String: Any] = [:]
    private let lock = OSAllocatedUnfairLock()

    public static let shared = DIContainer()

    public init() {}

    public func register<T>(_ type: T.Type, factory: @escaping @Sendable (DIContainer) throws -> T) {
        let key = String(describing: type)
        lock.lock()
        factories[key] = factory
        lock.unlock()
    }

    public func registerSingleton<T>(_ type: T.Type, factory: @escaping @Sendable (DIContainer) throws -> T) {
        let key = String(describing: type)
        lock.lock()
        let existingFactory = factories[key]
        lock.unlock()
        if existingFactory != nil { return }

        let singletonFactory: @Sendable (DIContainer) throws -> Any = { container in
            container.lock.lock()
            if let existing = container.singletons[key] {
                container.lock.unlock()
                return existing
            }
            container.lock.unlock()

            let instance = try factory(container)

            container.lock.lock()
            container.singletons[key] = instance
            container.lock.unlock()
            return instance
        }

        lock.lock()
        factories[key] = singletonFactory
        lock.unlock()
    }

    public func resolve<T>(_ type: T.Type = T.self) throws -> T {
        let key = String(describing: type)
        lock.lock()
        let factory = factories[key]
        lock.unlock()

        guard let factory = factory else {
            throw DIError.notRegistered(key)
        }

        let instance = try factory(self)
        guard let result = instance as? T else {
            throw DIError.notRegistered(key)
        }
        return result
    }

    public func resolveOptional<T>(_ type: T.Type = T.self) -> T? {
        try? resolve(type)
    }

    public func reset() {
        lock.lock()
        factories.removeAll()
        singletons.removeAll()
        lock.unlock()
    }
}
