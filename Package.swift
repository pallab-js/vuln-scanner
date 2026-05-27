// swift-tools-version: 6.0
import PackageDescription

#if os(macOS)
let testingFrameworkPath = "/Library/Developer/CommandLineTools/Library/Developer/Frameworks"
let testingLibPath = "/Library/Developer/CommandLineTools/Library/Developer/usr/lib"
let testSwiftSettings: [SwiftSetting] = [
    .unsafeFlags(["-F", testingFrameworkPath]),
    .unsafeFlags(["-L", testingLibPath]),
]
let testLinkerSettings: [LinkerSetting] = [
    .unsafeFlags(["-Xlinker", "-rpath", "-Xlinker", testingFrameworkPath]),
    .unsafeFlags(["-Xlinker", "-rpath", "-Xlinker", testingLibPath]),
    .unsafeFlags(["-Xlinker", "-F", "-Xlinker", testingFrameworkPath]),
]
#else
let testSwiftSettings: [SwiftSetting] = []
let testLinkerSettings: [LinkerSetting] = []
#endif

let package = Package(
    name: "LANScanner",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .executable(name: "LANScanner", targets: ["App"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.65.0"),
        .package(url: "https://github.com/groue/GRDB.swift.git", from: "6.29.0"),
    ],
    targets: [
        .target(
            name: "Core",
            dependencies: [
                .product(name: "GRDB", package: "grdb.swift"),
            ]
        ),
        .target(
            name: "NetScan",
            dependencies: [
                "Core",
                .product(name: "NIO", package: "swift-nio"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
            ]
        ),
        .target(
            name: "Engine",
            dependencies: ["Core", "NetScan"],
            resources: [.process("Resources")]
        ),
        .target(
            name: "API",
            dependencies: [
                "Core",
                "NetScan",
                "Engine",
                .product(name: "NIO", package: "swift-nio"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
            ]
        ),
        .target(
            name: "UI",
            dependencies: ["Core", "NetScan", "Engine", "API"]
        ),
        .executableTarget(
            name: "App",
            dependencies: ["Core", "NetScan", "Engine", "UI", "API"]
        ),
        .testTarget(
            name: "CoreTests",
            dependencies: ["Core"],
            swiftSettings: testSwiftSettings,
            linkerSettings: testLinkerSettings
        ),
        .testTarget(
            name: "NetScanTests",
            dependencies: ["NetScan", "Core"],
            swiftSettings: testSwiftSettings,
            linkerSettings: testLinkerSettings
        ),
        .testTarget(
            name: "EngineTests",
            dependencies: ["Engine", "NetScan", "Core"],
            swiftSettings: testSwiftSettings,
            linkerSettings: testLinkerSettings
        ),
        .testTarget(
            name: "APITests",
            dependencies: ["API", "Core", "NetScan", "Engine"],
            swiftSettings: testSwiftSettings,
            linkerSettings: testLinkerSettings
        ),
    ]
)
