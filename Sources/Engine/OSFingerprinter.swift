import Foundation
import Core

public struct OSFingerprinter: Sendable {
    private let logger = Logger(category: .mapping)

    public init() {}

    public func infer(ports: [ScanPort]) -> String? {
        var candidates: [(os: String, weight: Int)] = []

        for port in ports where port.state == .open {
            if let os = fingerBanner(port.banner) {
                candidates.append((os, 5))
            }
            if let os = fingerPorts(port) {
                candidates.append((os, 2))
            }
        }

        guard !candidates.isEmpty else { return nil }

        let weighted = Dictionary(grouping: candidates, by: \.os)
            .mapValues { $0.reduce(0) { $0 + $1.weight } }

        return weighted.max(by: { $0.value < $1.value })?.key
    }

    private func fingerBanner(_ banner: String?) -> String? {
        guard let banner = banner else { return nil }

        if banner.contains("SSH-") {
            if banner.localizedCaseInsensitiveContains("ubuntu") { return "Ubuntu Linux" }
            if banner.localizedCaseInsensitiveContains("debian") { return "Debian Linux" }
            if banner.localizedCaseInsensitiveContains("centos") { return "CentOS Linux" }
            if banner.localizedCaseInsensitiveContains("red hat") || banner.contains("RHEL") { return "Red Hat Linux" }
            if banner.localizedCaseInsensitiveContains("freebsd") { return "FreeBSD" }
            if banner.localizedCaseInsensitiveContains("openbsd") { return "OpenBSD" }
            if banner.contains("Apple") || banner.contains("Darwin") { return "macOS" }
            return "Linux (SSH)"
        }

        if let serverHeader = extractHTTPHeader(banner, header: "Server") {
            if serverHeader.localizedCaseInsensitiveContains("ubuntu") { return "Ubuntu Linux" }
            if serverHeader.localizedCaseInsensitiveContains("debian") { return "Debian Linux" }
            if serverHeader.localizedCaseInsensitiveContains("centos") { return "CentOS Linux" }
            if serverHeader.localizedCaseInsensitiveContains("red hat") { return "Red Hat Linux" }
            if serverHeader.localizedCaseInsensitiveContains("win") || serverHeader.contains("IIS") { return "Windows" }
            if serverHeader.localizedCaseInsensitiveContains("freebsd") { return "FreeBSD" }
            if serverHeader.localizedCaseInsensitiveContains("openbsd") { return "OpenBSD" }
        }

        if let via = extractHTTPHeader(banner, header: "Via") {
            if via.localizedCaseInsensitiveContains("win") { return "Windows" }
        }

        return nil
    }

    private func fingerPorts(_ port: ScanPort) -> String? {
        guard port.state == .open else { return nil }

        switch port.number {
        case 3389: return "Windows"
        case 445: return "Windows"
        case 137, 138, 139: return "Windows"
        case 5353: return "macOS"
        case 62078: return "macOS"
        default: return nil
        }
    }

    private func extractHTTPHeader(_ banner: String, header: String) -> String? {
        let pattern = "(?i)\(header):\\s*(.*)"
        let nsString = banner as NSString
        guard let regex = try? NSRegularExpression(pattern: pattern),
              let match = regex.firstMatch(in: banner, range: NSRange(location: 0, length: nsString.length)),
              match.numberOfRanges > 1 else { return nil }
        let range = match.range(at: 1)
        guard range.location != NSNotFound else { return nil }
        return nsString.substring(with: range).trimmingCharacters(in: .whitespaces).components(separatedBy: "\r").first
    }
}
