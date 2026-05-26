import SwiftUI
import Charts
import Core

public struct ContentView: View {
    @State private var viewModel = ScannerViewModel()

    public init() {}

    public var body: some View {
        NavigationSplitView {
            deviceList
        } detail: {
            if let device = viewModel.selectedDevice {
                deviceDetail(device: device)
            } else {
                emptyState
            }
        }
        .toolbar { toolbarContent }
        .frame(minWidth: 900, minHeight: 600)
    }

    // MARK: - Device List
    private var deviceList: some View {
        List(selection: $viewModel.selectedDevice) {
            ForEach(viewModel.devices) { device in
                DeviceRow(device: device)
                    .tag(device)
            }
        }
        .listStyle(.sidebar)
        .frame(minWidth: 250)
    }

    // MARK: - Empty State
    private var emptyState: some View {
        VStack(spacing: 20) {
            Image(systemName: "network.slash")
                .font(.system(size: 48))
                .foregroundStyle(.secondary)
            Text("No scan results")
                .font(.title2)
            Text("Click Start Scan to discover devices on your network")
                .font(.subheadline)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - Device Detail
    private func deviceDetail(device: Device) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                deviceHeader(device: device)
                portTable(device: device)
                vulnSection(device: device)
            }
            .padding()
        }
    }

    private func deviceHeader(device: Device) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: "desktopcomputer")
                    .font(.title)
                Text(device.host ?? device.ip)
                    .font(.title)
                    .bold()
            }
            HStack(spacing: 16) {
                Label(device.ip, systemImage: "network")
                if let mac = device.mac {
                    Label(mac, systemImage: "circle.dotted")
                }
                if let os = device.os {
                    Label(os, systemImage: "gearshape")
                }
            }
            .font(.caption)
            .foregroundStyle(.secondary)
        }
    }

    private func portTable(device: Device) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Open Ports (\(device.ports.filter { $0.state == .open }.count))")
                .font(.headline)

            if device.ports.isEmpty {
                Text("Port scan data not available")
                    .foregroundStyle(.secondary)
                    .font(.subheadline)
            } else {
                Chart {
                    ForEach(device.ports.filter { $0.state == .open }.prefix(20)) { port in
                        BarMark(
                            x: .value("Port", "\(port.number)"),
                            y: .value("Count", 1)
                        )
                        .foregroundStyle(by: .value("Service", port.service ?? "unknown"))
                    }
                }
                .frame(height: 150)

                Table(device.ports.filter { $0.state == .open }.sorted()) {
                    TableColumn("Port") { port in
                        Text("\(port.number)")
                    }
                    TableColumn("State") { port in
                        Text(port.state.rawValue.capitalized)
                    }
                    TableColumn("Service") { port in
                        Text(port.service ?? "-")
                    }
                    TableColumn("Banner") { port in
                        Text(port.banner ?? "-")
                            .lineLimit(1)
                            .truncationMode(.tail)
                    }
                }
                .tableStyle(.bordered)
            }
        }
    }

    private func vulnSection(device: Device) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Vulnerabilities (\(device.vulnerabilities.count))")
                .font(.headline)

            if device.vulnerabilities.isEmpty {
                Text("No vulnerabilities detected")
                    .foregroundStyle(.secondary)
            } else {
                Chart {
                    ForEach(device.vulnerabilities) { vuln in
                        BarMark(
                            x: .value("Severity", vuln.severity),
                            y: .value("Count", 1)
                        )
                        .foregroundStyle(by: .value("ID", vuln.id))
                    }
                }
                .frame(height: 100)
                .chartXScale(domain: 0...10)

                ForEach(device.vulnerabilities.sorted()) { vuln in
                    VulnRow(vuln: vuln)
                }
            }
        }
    }

    // MARK: - Toolbar
    @ToolbarContentBuilder
    private var toolbarContent: some ToolbarContent {
        ToolbarItem(placement: .primaryAction) {
            HStack {
                if viewModel.isScanning {
                    ProgressView()
                        .progressViewStyle(.linear)
                        .frame(width: 100)
                    Button("Stop", action: { viewModel.stopScan() })
                } else {
                    Button(action: { viewModel.startScan() }) {
                        Label("Start Scan", systemImage: "play.fill")
                    }
                }

                Button(action: exportCSV) {
                    Label("Export CSV", systemImage: "square.and.arrow.down")
                }
                .disabled(viewModel.devices.isEmpty)
            }
        }

        ToolbarItem(placement: .status) {
            HStack {
                Circle()
                    .fill(viewModel.isScanning ? Color.orange : Color.green)
                    .frame(width: 8, height: 8)
                Text(viewModel.statusMessage)
                    .font(.caption)
            }
        }
    }

    private func exportCSV() {
        let csv = viewModel.exportCSV()
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.commaSeparatedText]
        panel.nameFieldStringValue = "scan-report.csv"

        panel.begin { response in
            if response == .OK, let url = panel.url {
                try? csv.write(to: url, atomically: true, encoding: .utf8)
                Logger.ui.info("CSV exported to \(url.path)")
            }
        }
    }
}

// MARK: - Supporting Views
private struct DeviceRow: View {
    let device: Device

    var body: some View {
        HStack {
            VStack(alignment: .leading) {
                Text(device.host ?? device.ip)
                    .font(.body)
                Text(device.ip)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if !device.vulnerabilities.isEmpty {
                HStack(spacing: 2) {
                    let critical = device.vulnerabilities.filter { $0.severity >= 9 }.count
                    if critical > 0 {
                        Text("\(critical)")
                            .font(.caption2)
                            .padding(.horizontal, 4)
                            .background(Color.red)
                            .foregroundStyle(.white)
                            .clipShape(.capsule)
                    }
                }
            }
        }
        .padding(.vertical, 4)
    }
}

private struct VulnRow: View {
    let vuln: Vuln

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            severityBadge(score: vuln.severity)
            VStack(alignment: .leading, spacing: 2) {
                Text(vuln.id)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(vuln.description)
                    .font(.body)
                if let rec = vuln.recommendation {
                    Text("Recommendation: \(rec)")
                        .font(.caption)
                        .foregroundStyle(.blue)
                }
            }
        }
        .padding(8)
        .background(Color(nsColor: .windowBackgroundColor))
        .clipShape(.rect(cornerRadius: 6))
    }

    private func severityBadge(score: Double) -> some View {
        let level = SeverityLevel.from(score: score)
        let color: Color = switch level {
        case .critical: .red
        case .high: .orange
        case .medium: .yellow
        case .low: .blue
        case .info: .gray
        }
        return Text(String(format: "%.1f", score))
            .font(.caption2)
            .bold()
            .foregroundStyle(.white)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color)
            .clipShape(.capsule)
    }
}
