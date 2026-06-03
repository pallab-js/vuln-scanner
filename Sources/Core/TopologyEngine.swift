import Foundation

public struct TopologyNode: Identifiable, Sendable, Hashable {
    public let id: String
    public let ip: String
    public let host: String?
    public let riskScore: Double
    public let openPortCount: Int
    public var x: Double
    public var y: Double
}

public struct TopologyEdge: Identifiable, Sendable, Hashable {
    public var id: String { "\(from)-\(to)" }
    public let from: String
    public let to: String
}

public struct TopologyLayout: Sendable {
    public let nodes: [TopologyNode]
    public let edges: [TopologyEdge]

    public init(devices: [Device]) {
        var nodes = devices.map { device -> TopologyNode in
            TopologyNode(
                id: device.id, ip: device.ip, host: device.host,
                riskScore: device.riskScore,
                openPortCount: device.ports.filter { $0.state == .open }.count,
                x: 0, y: 0
            )
        }

        let edges: [TopologyEdge] = {
            guard nodes.count > 1 else { return [] }
            var e: [TopologyEdge] = []
            let limit = min(nodes.count, 50)
            for i in 0..<limit {
                for j in (i + 1)..<limit {
                    e.append(TopologyEdge(from: nodes[i].id, to: nodes[j].id))
                }
            }
            return e
        }()

        nodes = Self.layout(nodes: nodes, edges: edges, width: 360, height: 360, iterations: 80)
        self.nodes = nodes
        self.edges = edges
    }

    public static func layout(nodes: [TopologyNode], edges: [TopologyEdge], width: Double, height: Double, iterations: Int) -> [TopologyNode] {
        guard !nodes.isEmpty else { return [] }
        var pos = nodes
        let cX = width / 2, cY = height / 2

        let angle = 2 * Double.pi / Double(max(pos.count, 1))
        for i in pos.indices {
            pos[i].x = cX + cos(angle * Double(i)) * width * 0.3
            pos[i].y = cY + sin(angle * Double(i)) * height * 0.3
        }

        let idToIdx = Dictionary(uniqueKeysWithValues: pos.enumerated().map { ($1.id, $0) })
        var vel = [(dx: Double, dy: Double)](repeating: (0, 0), count: pos.count)

        for iter in 0..<iterations {
            let temp = max(0.5, 1.0 - Double(iter) / Double(iterations)) * 15
            var fx = [Double](repeating: 0, count: pos.count)
            var fy = [Double](repeating: 0, count: pos.count)

            for i in pos.indices {
                for j in pos.indices where i != j {
                    let dx = pos[i].x - pos[j].x
                    let dy = pos[i].y - pos[j].y
                    let d = max(hypot(dx, dy), 1)
                    let r = 3000 / (d * d)
                    fx[i] += dx / d * r
                    fy[i] += dy / d * r
                }
            }

            for edge in edges {
                guard let fi = idToIdx[edge.from], let ti = idToIdx[edge.to] else { continue }
                let dx = pos[ti].x - pos[fi].x
                let dy = pos[ti].y - pos[fi].y
                let d = max(hypot(dx, dy), 1)
                let a = d / 80
                fx[fi] += dx / d * a
                fy[fi] += dy / d * a
                fx[ti] -= dx / d * a
                fy[ti] -= dy / d * a
            }

            for i in pos.indices {
                vel[i].dx = (vel[i].dx + fx[i]) * 0.85
                vel[i].dy = (vel[i].dy + fy[i]) * 0.85
                let s = hypot(vel[i].dx, vel[i].dy)
                if s > temp {
                    vel[i].dx = vel[i].dx / s * temp
                    vel[i].dy = vel[i].dy / s * temp
                }
                pos[i].x = max(15, min(width - 15, pos[i].x + vel[i].dx))
                pos[i].y = max(15, min(height - 15, pos[i].y + vel[i].dy))
            }
        }
        return pos
    }
}
