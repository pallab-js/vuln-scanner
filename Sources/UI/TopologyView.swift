import SwiftUI
import SpriteKit
import Core

final class TopologyScene: SKScene {
    var topology: TopologyLayout? {
        didSet { rebuildScene() }
    }
    var onSelectDevice: ((String) -> Void)?

    private var nodeSprites: [String: SKShapeNode] = [:]
    private var labelNodes: [String: SKLabelNode] = [:]
    private var edgeNodes: [SKShapeNode] = []

    override func didMove(to view: SKView) {
        backgroundColor = .clear
        scaleMode = .resizeFill
    }

    private func rebuildScene() {
        removeAllChildren()
        nodeSprites.removeAll()
        labelNodes.removeAll()
        edgeNodes.removeAll()

        guard let topo = topology else { return }
        let w = size.width > 0 ? size.width : 400
        let h = size.height > 0 ? size.height : 400

        let positioned = TopologyLayout.layout(
            nodes: topo.nodes, edges: topo.edges,
            width: w, height: h, iterations: 80
        )

        for edge in topo.edges {
            guard let from = positioned.first(where: { $0.id == edge.from }),
                  let to = positioned.first(where: { $0.id == edge.to }) else { continue }
            let path = CGMutablePath()
            path.move(to: CGPoint(x: from.x, y: from.y))
            path.addLine(to: CGPoint(x: to.x, y: to.y))
            let line = SKShapeNode(path: path)
            line.strokeColor = NSColor.separatorColor
            line.lineWidth = 1
            line.alpha = 0.4
            addChild(line)
            edgeNodes.append(line)
        }

        for node in positioned {
            let radius = max(12, min(24, CGFloat(node.openPortCount) * 4 + 10))
            let sprite = SKShapeNode(circleOfRadius: radius)
            sprite.position = CGPoint(x: node.x, y: node.y)
            sprite.fillColor = riskColor(node.riskScore)
            sprite.strokeColor = NSColor.controlTextColor.withAlphaComponent(0.2)
            sprite.lineWidth = 1.5
            sprite.name = node.id
            sprite.isUserInteractionEnabled = true
            addChild(sprite)
            nodeSprites[node.id] = sprite

            if let host = node.host {
                let label = SKLabelNode(text: host.count > 12 ? String(host.prefix(10)) + "…" : host)
                label.fontSize = 9
                label.fontColor = NSColor.secondaryLabelColor
                label.position = CGPoint(x: node.x, y: node.y - radius - 12)
                label.fontName = "Helvetica Neue"
                addChild(label)
                labelNodes[node.id] = label
            }

            let ipLabel = SKLabelNode(text: node.ip)
            ipLabel.fontSize = 7
            ipLabel.fontColor = NSColor.tertiaryLabelColor
            ipLabel.position = CGPoint(x: node.x, y: node.y - radius - 22)
            ipLabel.fontName = "Helvetica Neue"
            addChild(ipLabel)
            labelNodes["ip-\(node.id)"] = ipLabel
        }
    }

    override func mouseDown(with event: NSEvent) {
        let loc = event.location(in: self)
        if let node = nodes(at: loc).compactMap({ $0 as? SKShapeNode }).first,
           let id = node.name {
            onSelectDevice?(id)
        }
    }

    private func riskColor(_ score: Double) -> NSColor {
        switch score {
        case 7...: return .systemRed
        case 4...: return .systemOrange
        case 1...: return .systemYellow
        default:   return .systemGreen
        }
    }
}

public struct TopologyView: View {
    let devices: [Device]
    let onSelect: (String) -> Void

    public init(devices: [Device], onSelect: @escaping (String) -> Void) {
        self.devices = devices
        self.onSelect = onSelect
    }

    public var body: some View {
        let topo = TopologyLayout(devices: devices)
        SpriteView(scene: makeScene(topo: topo), debugOptions: [])
            .aspectRatio(1, contentMode: .fit)
            .frame(minWidth: 360, minHeight: 360)
    }

    private func makeScene(topo: TopologyLayout) -> TopologyScene {
        let scene = TopologyScene()
        scene.topology = topo
        scene.onSelectDevice = { id in
            onSelect(id)
        }
        return scene
    }
}
