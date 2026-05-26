import Testing
import Core

@Test func diContainerResolvesRegisteredService() throws {
    let container = DIContainer()
    container.register(String.self) { _ in "test" }
    let value: String = try container.resolve()
    #expect(value == "test")
    container.reset()
}

@Test func diContainerThrowsOnUnregisteredService() {
    let container = DIContainer()
    #expect(throws: DIError.self) {
        try container.resolve() as String
    }
    container.reset()
}

@Test func loggerFormatsMetadata() {
    let log = Logger(category: .app)
    let result = log.withMetadata("test", metadata: ["key": "value"])
    #expect(result == "test | key=value")
}
