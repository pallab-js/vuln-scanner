import Foundation

public struct Tag: Codable, Identifiable, Sendable, Hashable {
    public var id: String { name }
    public var name: String
    public var color: String  // hex color, e.g. "#FF0000"

    public init(name: String, color: String = "#666666") {
        self.name = name
        self.color = color
    }
}

public final class TagStore: Sendable {
    public static let shared = TagStore()
    private let logger = Logger(category: .config)

    private var storageURL: URL? {
        guard let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            return nil
        }
        let dir = support.appendingPathComponent("com.lanscanner")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("tags.json")
    }

    private init() {}

    public func load() -> [String: [Tag]] {
        guard let url = storageURL, let data = try? Data(contentsOf: url) else {
            return [:]
        }
        do {
            return try JSONDecoder().decode([String: [Tag]].self, from: data)
        } catch {
            logger.error("Failed to decode tags: \(error.localizedDescription)")
            return [:]
        }
    }

    public func save(_ tags: [String: [Tag]]) {
        guard let url = storageURL else { return }
        do {
            let data = try JSONEncoder().encode(tags)
            try data.write(to: url, options: .atomic)
        } catch {
            logger.error("Failed to save tags: \(error.localizedDescription)")
        }
    }

    public func tags(for ip: String) -> [Tag] {
        load()[ip, default: []]
    }

    public func addTag(_ tag: Tag, to ip: String) {
        var all = load()
        var deviceTags = all[ip, default: []]
        if !deviceTags.contains(tag) {
            deviceTags.append(tag)
            all[ip] = deviceTags
            save(all)
        }
    }

    public func removeTag(_ tag: Tag, from ip: String) {
        var all = load()
        all[ip]?.removeAll { $0 == tag }
        if all[ip]?.isEmpty == true { all.removeValue(forKey: ip) }
        save(all)
    }

    public func allTags() -> [Tag] {
        Set(load().values.flatMap { $0 }).sorted { $0.name < $1.name }
    }
}
