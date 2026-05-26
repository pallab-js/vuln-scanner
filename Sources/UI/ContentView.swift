import SwiftUI
import Charts
import Core
import API
import Engine

public struct ContentView: View {
    @State private var viewModel = ScannerViewModel()
    @State private var showTopology = false

    public init() {}

    public var body: some View {
        NavigationSplitView {
            sidebar
        } detail: {
            if let device = viewModel.selectedDevice {
                deviceDetail(device: device)
            } else {
                dashboard
            }
        }
        .toolbar { toolbarContent }
        .frame(minWidth: 900, minHeight: 600)
        .sheet(isPresented: $viewModel.showConfig) {
            ConfigSheet(config: $viewModel.config, viewModel: viewModel)
        }
        .alert("Rules Update", isPresented: .init(
            get: { viewModel.rulesUpdateError != nil },
            set: { if !$0 { viewModel.rulesUpdateError = nil } }
        )) {
            Button("OK") { viewModel.rulesUpdateError = nil }
        } message: {
            Text(viewModel.rulesUpdateError ?? "")
        }
        .sheet(isPresented: $showTopology) {
            topologySheet
        }
        .sheet(isPresented: $viewModel.showRulesManager) {
            RulesManagerView(viewModel: viewModel)
        }
        .sheet(isPresented: $viewModel.showRuleEditor) {
            RuleEditorView(viewModel: viewModel, rule: viewModel.editingRule)
        }
        .keyboardShortcutHandling(viewModel: viewModel)
    }

    // MARK: - Sidebar
    private var sidebar: some View {
        VStack(spacing: 0) {
            searchBar
                .padding(.horizontal, 8)
                .padding(.vertical, 6)

            Picker("", selection: .init(
                get: { viewModel.selectedHistoryScanID == nil ? "current" : "history" },
                set: { if $0 == "current" { viewModel.selectedHistoryScanID = nil } }
            )) {
                Text("Current Scan").tag("current")
                if viewModel.selectedHistoryScanID != nil {
                    Text("History").tag("history")
                }
            }
            .pickerStyle(.segmented)
            .padding(.horizontal, 8)
            .padding(.bottom, 4)

            Divider()

            let sourceDevices = viewModel.selectedHistoryScanID != nil ? viewModel.historyDevices : viewModel.devices

            if viewModel.selectedHistoryScanID != nil {
                HStack {
                    Button {
                        viewModel.selectedHistoryScanID = nil
                    } label: {
                        Label("Back to scan", systemImage: "chevron.left")
                    }
                    .buttonStyle(.plain)
                    .font(.caption)
                    Spacer()
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
            }

            tagFilterBar

            List(selection: $viewModel.selectedDevice) {
                let displayDevices = viewModel.tagFilter != nil ? viewModel.filteredDevicesWithTags : sourceDevices
                ForEach(displayDevices) { device in
                    DeviceRow(device: device, tags: viewModel.deviceTags[device.ip] ?? [])
                        .tag(device)
                        .transition(.slide)
                }
            }
            .listStyle(.sidebar)
            .frame(minWidth: 250)
            .animation(.easeInOut(duration: 0.3), value: sourceDevices)
        }
    }

    @ViewBuilder
    private var tagFilterBar: some View {
        let tags = viewModel.allKnownTags
        if !tags.isEmpty {
            VStack(alignment: .leading, spacing: 4) {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 4) {
                        Button("All") {
                            viewModel.tagFilter = nil
                        }
                        .font(.caption2)
                        .buttonStyle(.plain)
                        .foregroundStyle(viewModel.tagFilter == nil ? Color.accentColor : .secondary)
                        .bold(viewModel.tagFilter == nil)

                        ForEach(tags) { tag in
                            Button(tag.name) {
                                viewModel.tagFilter = viewModel.tagFilter == tag.name ? nil : tag.name
                            }
                            .font(.caption2)
                            .buttonStyle(.plain)
                            .foregroundStyle(viewModel.tagFilter == tag.name ? tagColor(tag.color) : .secondary)
                            .bold(viewModel.tagFilter == tag.name)
                        }
                    }
                    .padding(.horizontal, 8)
                }
            }
            .padding(.vertical, 4)
        }
    }

    private func tagColor(_ hex: String) -> Color {
        guard hex.hasPrefix("#"), let val = Int(hex.dropFirst(), radix: 16) else { return .gray }
        let r = Double((val >> 16) & 0xFF) / 255
        let g = Double((val >> 8) & 0xFF) / 255
        let b = Double(val & 0xFF) / 255
        return Color(.sRGB, red: r, green: g, blue: b, opacity: 1)
    }

    private var searchBar: some View {
        HStack {
            Image(systemName: "magnifyingglass")
                .foregroundStyle(.secondary)
            TextField("Filter by IP or hostname…", text: $viewModel.searchText)
                .textFieldStyle(.plain)
                .font(.subheadline)
            if !viewModel.searchText.isEmpty {
                Button {
                    viewModel.searchText = ""
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
            }
        }
        .padding(6)
        .background(Color(nsColor: .controlBackgroundColor))
        .clipShape(.rect(cornerRadius: 6))
    }

    // MARK: - Dashboard
    private var dashboard: some View {
        ScrollView {
            VStack(spacing: 24) {
                if viewModel.devices.isEmpty && viewModel.selectedHistoryScanID == nil {
                    emptyState
                } else {
                    let sourceDevices = viewModel.selectedHistoryScanID != nil ? viewModel.historyDevices : viewModel.devices
                    summaryCards(devices: sourceDevices)
                    complianceFilterBar
                    severityChart(devices: sourceDevices, compliance: viewModel.activeComplianceFilters)
                    recentDevices(devices: sourceDevices)
                }

                if viewModel.history.isEmpty && viewModel.devices.isEmpty {
                    EmptyView()
                } else {
                    Divider()
                    historySection
                    trendSection
                }
            }
            .padding(24)
        }
    }

    private var emptyState: some View {
        VStack(spacing: 20) {
            Image(systemName: "network.slash")
                .font(.system(size: 56))
                .foregroundStyle(.tertiary)
            Text("No scan results")
                .font(.title2).bold()
            Text("Configure scan settings, then hit Start Scan")
                .font(.subheadline)
                .foregroundStyle(.secondary)
            HStack(spacing: 16) {
                Button {
                    viewModel.showConfig = true
                } label: {
                    Label("Configure", systemImage: "gearshape")
                }
                .buttonStyle(.bordered)

                Button {
                    viewModel.startScan()
                } label: {
                    Label("Start Scan", systemImage: "play.fill")
                }
                .buttonStyle(.borderedProminent)
            }
            .padding(.top, 8)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func summaryCards(devices: [Device]) -> some View {
        let totalOpen = devices.reduce(0) { $0 + $1.ports.filter { $0.state == .open }.count }
        let totalVulns = devices.reduce(0) { $0 + $1.vulnerabilities.count }
        let avgRisk = devices.isEmpty ? 0 : devices.reduce(0.0) { $0 + $1.riskScore } / Double(devices.count)

        return LazyVGrid(columns: [GridItem(.adaptive(minimum: 160))], spacing: 16) {
            StatCard(title: "Devices", value: "\(devices.count)", icon: "desktopcomputer", color: .blue)
            StatCard(title: "Open Ports", value: "\(totalOpen)", icon: "door.left.hand.open", color: .orange)
            StatCard(title: "Vulnerabilities", value: "\(totalVulns)", icon: "exclamationmark.triangle", color: .red)
            StatCard(title: "Risk Score", value: String(format: "%.1f", avgRisk), icon: "gauge.medium", color: riskColor(avgRisk))
            StatCard(title: "Duration", value: String(format: "%.1fs", viewModel.scanDuration), icon: "clock", color: .purple)
        }
    }

    private var complianceFilterBar: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Compliance Filter").font(.caption).foregroundStyle(.secondary)
            HStack(spacing: 8) {
                ForEach(ComplianceFramework.allCases, id: \.self) { framework in
                    let isActive = viewModel.activeComplianceFilters.contains(framework)
                    Button {
                        if isActive {
                            viewModel.activeComplianceFilters.remove(framework)
                        } else {
                            viewModel.activeComplianceFilters.insert(framework)
                        }
                    } label: {
                        HStack(spacing: 4) {
                            if isActive {
                                Image(systemName: "checkmark.circle.fill").font(.caption2)
                            }
                            Text(framework.rawValue).font(.caption2).bold()
                        }
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(isActive ? Color.accentColor : Color(nsColor: .controlBackgroundColor))
                        .foregroundStyle(isActive ? .white : .primary)
                        .clipShape(.capsule)
                        .overlay(
                            Capsule().stroke(isActive ? Color.accentColor : Color.gray.opacity(0.3), lineWidth: 1)
                        )
                    }
                    .buttonStyle(.plain)
                }
                if !viewModel.activeComplianceFilters.isEmpty {
                    Button("Clear") { viewModel.activeComplianceFilters.removeAll() }
                        .font(.caption2).foregroundStyle(.secondary)
                        .buttonStyle(.plain)
                }
            }
            if !viewModel.activeComplianceFilters.isEmpty {
                Text("Showing vulns relevant to \(viewModel.complianceSummary)")
                    .font(.caption2).foregroundStyle(.secondary)
            }
        }
        .padding()
        .background(Color(nsColor: .windowBackgroundColor))
        .clipShape(.rect(cornerRadius: 10))
    }

    private func severityChart(devices: [Device], compliance: Set<ComplianceFramework> = []) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Vulnerability Severity Distribution")
                .font(.headline)

            let allVulns = devices.flatMap(\.vulnerabilities)
            let vulns = compliance.isEmpty ? allVulns : allVulns.filter { !Set($0.compliance).isDisjoint(with: compliance) }
            if vulns.isEmpty {
                Text("No vulnerabilities across scanned devices")
                    .foregroundStyle(.secondary).font(.subheadline)
            } else {
                Chart {
                    ForEach(SeverityLevel.allCases, id: \.self) { level in
                        let count = vulns.filter { SeverityLevel.from(score: $0.severity) == level }.count
                        if count > 0 {
                            BarMark(
                                x: .value("Severity", level.rawValue.capitalized),
                                y: .value("Count", count)
                            )
                            .foregroundStyle(by: .value("Severity", level.rawValue.capitalized))
                            .annotation(position: .top) {
                                Text("\(count)").font(.caption2).foregroundStyle(.secondary)
                            }
                        }
                    }
                }
                .chartForegroundStyleScale([
                    "CRITICAL": .red, "HIGH": .orange, "MEDIUM": .yellow,
                    "LOW": .blue, "INFO": .gray
                ])
                .frame(height: 180)
            }
        }
        .padding()
        .background(Color(nsColor: .windowBackgroundColor))
        .clipShape(.rect(cornerRadius: 10))
    }

    private func recentDevices(devices: [Device]) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Devices by Risk").font(.headline)

            let sorted = devices.sorted { $0.riskScore > $1.riskScore }
            ForEach(sorted.prefix(5)) { device in
                HStack {
                    Image(systemName: "circle.fill").font(.system(size: 8))
                        .foregroundStyle(riskColor(device.riskScore))
                    Text(device.host ?? device.ip).font(.body)
                    Spacer()
                    HStack(spacing: 4) {
                        Text("\(device.ports.filter { $0.state == .open }.count) ports")
                            .font(.caption).foregroundStyle(.secondary)
                        Text("\(device.vulnerabilities.count) vulns")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    Text(String(format: "%.1f", device.riskScore))
                        .font(.caption).bold()
                        .foregroundStyle(riskColor(device.riskScore))
                }
                .padding(.vertical, 4)
            }
        }
        .padding()
        .background(Color(nsColor: .windowBackgroundColor))
        .clipShape(.rect(cornerRadius: 10))
    }

    // MARK: - History Section
    private var historySection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Scan History (\(viewModel.history.count))")
                .font(.headline)

            if viewModel.history.isEmpty {
                Text("No previous scans").foregroundStyle(.secondary).font(.subheadline)
            } else {
                LazyVStack(spacing: 8) {
                    ForEach(viewModel.history.prefix(10)) { summary in
                        Button {
                            viewModel.selectHistoryScan(scanID: summary.scanID)
                        } label: {
                            HStack {
                                Circle()
                                    .fill(riskColor(summary.riskScore))
                                    .frame(width: 8, height: 8)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(summary.timestamp.formatted(date: .abbreviated, time: .shortened))
                                        .font(.body)
                                    Text("\(summary.deviceCount) devices · \(summary.totalVulnerabilities) vulns · \(String(format: "%.1f", summary.riskScore)) risk")
                                        .font(.caption).foregroundStyle(.secondary)
                                }
                                Spacer()
                                Text(summary.config.portRange.lowerBound == 1 && summary.config.portRange.upperBound == 1024 ? "Well-known" : "\(summary.config.portRange.lowerBound)-\(summary.config.portRange.upperBound)")
                                    .font(.caption2).foregroundStyle(.tertiary)
                                    .padding(.horizontal, 4).padding(.vertical, 2)
                                    .background(Color(nsColor: .controlBackgroundColor))
                                    .clipShape(.rect(cornerRadius: 4))
                            }
                            .padding(.vertical, 2)
                        }
                        .buttonStyle(.plain)
                        .contextMenu {
                            Button("Load scan") { viewModel.selectHistoryScan(scanID: summary.scanID) }
                            Divider()
                            Button("Delete scan", role: .destructive) { viewModel.deleteHistoryScan(scanID: summary.scanID) }
                        }
                    }
                }
            }
        }
        .padding()
        .background(Color(nsColor: .windowBackgroundColor))
        .clipShape(.rect(cornerRadius: 10))
    }

    // MARK: - Trend Section
    private var trendSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Vulnerabilities Over Time")
                .font(.headline)

            let points = viewModel.trends.vulnsOverTime
            if points.isEmpty {
                Text("Insufficient scan history for trend data")
                    .foregroundStyle(.secondary).font(.subheadline)
            } else {
                Chart {
                    ForEach(points) { point in
                        LineMark(
                            x: .value("Date", point.date),
                            y: .value("Vulns", point.value)
                        )
                        .foregroundStyle(.red)
                        PointMark(
                            x: .value("Date", point.date),
                            y: .value("Vulns", point.value)
                        )
                        .foregroundStyle(.red)
                    }
                }
                .frame(height: 150)
                .chartXAxis { AxisMarks(values: .automatic) { AxisValueLabel(format: .dateTime.month().day()) } }

                if !viewModel.trends.topCVE.isEmpty {
                    Text("Top CVEs").font(.headline).padding(.top, 8)
                    ForEach(viewModel.trends.topCVE.prefix(5)) { cve in
                        HStack {
                            Text(cve.cve).font(.caption).bold()
                            Spacer()
                            Text("× \(cve.count)").font(.caption).foregroundStyle(.secondary)
                        }
                        .padding(.vertical, 2)
                    }
                }
            }
        }
        .padding()
        .background(Color(nsColor: .windowBackgroundColor))
        .clipShape(.rect(cornerRadius: 10))
    }

    // MARK: - Device Detail
    private func deviceDetail(device: Device) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                deviceHeader(device: device)
                HStack(spacing: 16) {
                    StatCard(title: "Open Ports", value: "\(device.ports.filter { $0.state == .open }.count)", icon: "door.left.hand.open", color: .orange, compact: true)
                    StatCard(title: "Vulnerabilities", value: "\(device.vulnerabilities.count)", icon: "exclamationmark.triangle", color: .red, compact: true)
                    StatCard(title: "Risk Score", value: String(format: "%.1f", device.riskScore), icon: "gauge.medium", color: riskColor(device.riskScore), compact: true)
                }
                tagSection(device: device)
                portSection(device: device)
                vulnSection(device: device)
            }
            .padding()
        }
    }

    private func deviceHeader(device: Device) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: "desktopcomputer")
                    .font(.title)
                    .foregroundStyle(riskColor(device.riskScore))
                Text(device.host ?? device.ip)
                    .font(.title).bold()
                riskBadge(score: device.riskScore)
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

    private func tagSection(device: Device) -> some View {
        let deviceTags = viewModel.deviceTags[device.ip, default: []]
        return VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Tags").font(.headline)
                Spacer()
                Button {
                    viewModel.editingTagDevice = device.ip
                    viewModel.showTagEditor = true
                } label: {
                    Image(systemName: "plus.circle").font(.caption)
                }
                .buttonStyle(.plain)
                .help("Add tag")
            }

            if deviceTags.isEmpty {
                Text("No tags").foregroundStyle(.secondary).font(.subheadline)
            } else {
                HStack(spacing: 6) {
                    ForEach(deviceTags) { tag in
                        HStack(spacing: 2) {
                            Text(tag.name).font(.caption2).bold()
                            Button {
                                viewModel.removeTag(tag, from: device.ip)
                            } label: {
                                Image(systemName: "xmark").font(.system(size: 6))
                            }
                            .buttonStyle(.plain)
                            .foregroundStyle(.white.opacity(0.7))
                        }
                        .padding(.horizontal, 6).padding(.vertical, 3)
                        .background(tagColor(tag.color))
                        .foregroundStyle(.white)
                        .clipShape(.capsule)
                    }
                }
            }
        }
        .padding()
        .background(Color(nsColor: .windowBackgroundColor))
        .clipShape(.rect(cornerRadius: 10))
        .sheet(isPresented: $viewModel.showTagEditor) {
            if let ip = viewModel.editingTagDevice {
                TagEditorView(viewModel: viewModel, deviceIP: ip)
            }
        }
    }

    private func portSection(device: Device) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            let tcpOpen = device.ports.filter { $0.state == .open && $0.transport == .tcp }.count
            let udpOpen = device.ports.filter { $0.state == .open && $0.transport == .udp }.count
            Text("Open Ports (\(tcpOpen + udpOpen) — TCP:\(tcpOpen) UDP:\(udpOpen))")
                .font(.headline)

            if device.ports.isEmpty {
                Text("Port scan data not available")
                    .foregroundStyle(.secondary).font(.subheadline)
            } else {
                Chart {
                    ForEach(device.ports.filter { $0.state == .open }.prefix(20)) { port in
                        BarMark(x: .value("Port", "\(port.number)"), y: .value("Count", 1))
                            .foregroundStyle(by: .value("Protocol", port.transport.rawValue))
                    }
                }
                .frame(height: 150)

                Table(device.ports.filter { $0.state == .open }.sorted()) {
                    TableColumn("Port") { port in Text("\(port.number)") }
                    TableColumn("Protocol") { port in
                        Text(port.transport.rawValue)
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    TableColumn("State") { port in Text(port.state.rawValue.capitalized) }
                    TableColumn("Service") { port in Text(port.service ?? "-") }
                    TableColumn("Banner") { port in
                        Text(port.banner ?? "-").lineLimit(1).truncationMode(.tail)
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
                Text("No vulnerabilities detected").foregroundStyle(.secondary)
            } else {
                Chart {
                    ForEach(device.vulnerabilities) { vuln in
                        BarMark(x: .value("Severity", vuln.severity), y: .value("Count", 1))
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
                    ProgressView().progressViewStyle(.linear).frame(width: 100)
                    Button("Stop", action: { viewModel.stopScan() })
                } else {
                    Button(action: { viewModel.startScan() }) {
                        Label("Start Scan", systemImage: "play.fill")
                    }
                    .help("Start Scan (⌘R)")
                }

                Button(action: { showTopology = true }) {
                    Label("Topology Map", systemImage: "point.3.connected.trianglepath.dotted")
                }
                .help("Network Topology Map")
                .disabled(viewModel.devices.isEmpty && viewModel.selectedHistoryScanID == nil)

                Button(action: { viewModel.showRulesManager = true }) {
                    Label("Custom Rules", systemImage: "doc.badge.gearshape")
                }
                .help("Manage Custom Rules")

                if !viewModel.config.rulesURL.isEmpty {
                    Button(action: { viewModel.updateRules() }) {
                        Label("Update Rules", systemImage: "arrow.down.circle")
                    }
                    .disabled(viewModel.isUpdatingRules)
                    .help("Fetch latest rules")
                }

                Button(action: { viewModel.showConfig = true }) {
                    Label("Configure", systemImage: "gearshape")
                }
                .help("Scan Settings (⌘,)")

                Menu {
                    Button(action: exportHTML) { Label("Export HTML Report", systemImage: "doc.text") }
                    Divider()
                    Button(action: exportCSV) { Label("Export as CSV", systemImage: "tablecells") }
                    Button(action: exportJSON) { Label("Export as JSON", systemImage: "curlybraces") }
                } label: {
                    Label("Export", systemImage: "square.and.arrow.down")
                }
                .disabled(viewModel.devices.isEmpty && viewModel.historyDevices.isEmpty)
                .help("Export Results")
            }
        }

        ToolbarItem(placement: .status) {
            HStack(spacing: 8) {
                Circle()
                    .fill(viewModel.isScanning ? Color.orange : (viewModel.devices.isEmpty && viewModel.historyDevices.isEmpty) ? Color.gray : Color.green)
                    .frame(width: 8, height: 8)
                Text(viewModel.statusMessage)
                    .font(.caption)

                if viewModel.rulesVersion > 0 {
                    let stale = RuleUpdater.isCacheStale()
                    HStack(spacing: 3) {
                        Circle().fill(stale ? Color.orange : Color.green).frame(width: 5, height: 5)
                        Text("Rules v\(viewModel.rulesVersion)").font(.caption2).foregroundStyle(.secondary)
                    }
                }

                if viewModel.isUpdatingRules {
                    ProgressView().progressViewStyle(.circular).controlSize(.small).scaleEffect(0.6)
                }
            }
        }
    }

    private func exportHTML() {
        let html = viewModel.exportHTML()
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.html]
        panel.nameFieldStringValue = "scan-report.html"
        panel.begin { response in
            if response == .OK, let url = panel.url {
                try? html.write(to: url, atomically: true, encoding: .utf8)
                Logger.ui.info("HTML report exported to \(url.path)")
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

    private func exportJSON() {
        let json = viewModel.exportJSON()
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.json]
        panel.nameFieldStringValue = "scan-report.json"
        panel.begin { response in
            if response == .OK, let url = panel.url {
                try? json.write(to: url, atomically: true, encoding: .utf8)
                Logger.ui.info("JSON exported to \(url.path)")
            }
        }
    }

    private func riskColor(_ score: Double) -> Color {
        switch score { case 7...: .red case 4...: .orange case 1...: .yellow default: .green }
    }

    private func riskBadge(score: Double) -> some View {
        Text(String(format: "%.1f", score))
            .font(.caption).bold()
            .foregroundStyle(.white)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(riskColor(score))
            .clipShape(.capsule)
    }

    // MARK: - Topology Sheet
    private var topologySheet: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Network Topology").font(.headline)
                Spacer()
                Button("Close") { showTopology = false }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
            }
            .padding()

            let sourceDevices = viewModel.selectedHistoryScanID != nil ? viewModel.historyDevices : viewModel.devices

            if sourceDevices.count < 2 {
                VStack(spacing: 12) {
                    Image(systemName: "point.3.connected.trianglepath.dotted")
                        .font(.system(size: 40)).foregroundStyle(.tertiary)
                    Text("Need at least 2 devices to render topology")
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                TopologyView(devices: sourceDevices) { deviceID in
                    if let device = sourceDevices.first(where: { $0.id == deviceID }) {
                        viewModel.selectedDevice = device
                        showTopology = false
                    }
                }
                .padding()
            }
        }
        .frame(width: 500, height: 520)
    }
}

// MARK: - Supporting Views
private struct DeviceRow: View {
    let device: Device
    let tags: [Tag]

    var body: some View {
        HStack(spacing: 8) {
            Circle().fill(riskColor(device.riskScore)).frame(width: 8, height: 8)
            VStack(alignment: .leading, spacing: 2) {
                Text(device.host ?? device.ip).font(.body).lineLimit(1)
                Text(device.ip).font(.caption).foregroundStyle(.secondary)
                if !tags.isEmpty {
                    HStack(spacing: 3) {
                        ForEach(tags.prefix(3)) { tag in
                            Text(tag.name).font(.system(size: 7)).bold()
                                .padding(.horizontal, 4).padding(.vertical, 1)
                                .background(tagColor(tag.color).opacity(0.2))
                                .foregroundStyle(tagColor(tag.color))
                                .clipShape(.rect(cornerRadius: 3))
                        }
                        if tags.count > 3 {
                            Text("+\(tags.count - 3)").font(.system(size: 7)).foregroundStyle(.secondary)
                        }
                    }
                }
            }
            Spacer()
            HStack(spacing: 4) {
                if !device.vulnerabilities.isEmpty {
                    let critical = device.vulnerabilities.filter { $0.severity >= 9 }.count
                    let high = device.vulnerabilities.filter { $0.severity >= 7 && $0.severity < 9 }.count
                    if critical > 0 {
                        Text("\(critical)").font(.caption2).bold().foregroundStyle(.white)
                            .padding(.horizontal, 5).padding(.vertical, 1)
                            .background(Color.red).clipShape(.capsule)
                    }
                    if high > 0 {
                        Text("\(high)").font(.caption2).bold().foregroundStyle(.white)
                            .padding(.horizontal, 5).padding(.vertical, 1)
                            .background(Color.orange).clipShape(.capsule)
                    }
                }
                Text(String(format: "%.1f", device.riskScore))
                    .font(.caption2).bold().foregroundStyle(riskColor(device.riskScore))
            }
        }
        .padding(.vertical, 4)
    }

    private func riskColor(_ score: Double) -> Color {
        switch score { case 7...: .red case 4...: .orange case 1...: .yellow default: .green }
    }

    private func tagColor(_ hex: String) -> Color {
        guard hex.hasPrefix("#"), let val = Int(hex.dropFirst(), radix: 16) else { return .gray }
        let r = Double((val >> 16) & 0xFF) / 255
        let g = Double((val >> 8) & 0xFF) / 255
        let b = Double(val & 0xFF) / 255
        return Color(.sRGB, red: r, green: g, blue: b, opacity: 1)
    }
}

private struct VulnRow: View {
    let vuln: Vuln

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            severityBadge(score: vuln.severity)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 4) {
                    Text(vuln.id).font(.caption).foregroundStyle(.secondary)
                    if let cve = vuln.cve {
                        Text(cve).font(.caption2).foregroundStyle(.blue)
                            .padding(.horizontal, 4).background(Color.blue.opacity(0.1)).clipShape(.rect(cornerRadius: 3))
                    }
                }
                Text(vuln.description).font(.body)

                if !vuln.compliance.isEmpty {
                    HStack(spacing: 4) {
                        ForEach(vuln.compliance, id: \.self) { fw in
                            Text(fw.rawValue).font(.system(size: 7)).bold()
                                .padding(.horizontal, 4).padding(.vertical, 1)
                                .background(frameworkColor(fw).opacity(0.15))
                                .foregroundStyle(frameworkColor(fw))
                                .clipShape(.rect(cornerRadius: 3))
                        }
                    }
                }

                if let rec = vuln.recommendation {
                    Label(rec, systemImage: "lightbulb").font(.caption).foregroundStyle(.blue)
                }
            }
        }
        .padding(10)
        .background(Color(nsColor: .windowBackgroundColor))
        .clipShape(.rect(cornerRadius: 8))
    }

    private func frameworkColor(_ fw: ComplianceFramework) -> Color {
        switch fw {
        case .pciDSS: return .red
        case .hipaa: return .blue
        case .gdpr: return .purple
        case .soc2: return .green
        case .nist: return .orange
        }
    }

    private func severityBadge(score: Double) -> some View {
        let level = SeverityLevel.from(score: score)
        let color: Color = switch level {
        case .critical: .red case .high: .orange case .medium: .yellow case .low: .blue case .info: .gray
        }
        return VStack(spacing: 1) {
            Text(level.rawValue.prefix(1)).font(.caption).bold()
            Text(String(format: "%.1f", score)).font(.system(size: 8))
        }
        .foregroundStyle(.white)
        .frame(width: 28, height: 28)
        .background(color)
        .clipShape(.circle)
    }
}

private struct StatCard: View {
    let title: String
    let value: String
    let icon: String
    let color: Color
    var compact: Bool = false

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon).font(.title3).foregroundStyle(color).frame(width: 24)
            VStack(alignment: .leading, spacing: 2) {
                Text(value).font(.title2).bold()
                Text(title).font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .windowBackgroundColor))
        .clipShape(.rect(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(color.opacity(0.2), lineWidth: 1))
    }
}

// MARK: - Config Sheet
private struct ConfigSheet: View {
    @Binding var config: ScanConfig
    let viewModel: ScannerViewModel
    @Environment(\.dismiss) private var dismiss
    @State private var portFrom: Int
    @State private var portTo: Int
    @State private var udpFrom: Int
    @State private var udpTo: Int
    @State private var timeout: Double
    @State private var maxConcurrency: Int
    @State private var excludeText: String
    @State private var serviceDetection: Bool
    @State private var osDetection: Bool
    @State private var scanUDP: Bool
    @State private var webhookURL: String
    @State private var webhookEnabled: Bool
    @State private var subnetCIDR: String
    @State private var scheduleEnabled: Bool
    @State private var scheduleIntervalHours: Double
    @State private var apiEnabled: Bool
    @State private var apiPort: String
    @State private var autoUpdateRules: Bool
    @State private var rulesURL: String

    init(config: Binding<ScanConfig>, viewModel: ScannerViewModel) {
        _config = config
        self.viewModel = viewModel
        _portFrom = State(initialValue: config.wrappedValue.portRange.lowerBound)
        _portTo = State(initialValue: config.wrappedValue.portRange.upperBound)
        _udpFrom = State(initialValue: config.wrappedValue.udpPortRange.lowerBound)
        _udpTo = State(initialValue: config.wrappedValue.udpPortRange.upperBound)
        _timeout = State(initialValue: config.wrappedValue.timeout)
        _maxConcurrency = State(initialValue: config.wrappedValue.maxConcurrency)
        _excludeText = State(initialValue: config.wrappedValue.excludeIPs.joined(separator: ", "))
        _serviceDetection = State(initialValue: config.wrappedValue.serviceDetection)
        _osDetection = State(initialValue: config.wrappedValue.osDetection)
        _scanUDP = State(initialValue: config.wrappedValue.scanUDP)
        _webhookURL = State(initialValue: config.wrappedValue.webhookURL)
        _webhookEnabled = State(initialValue: config.wrappedValue.webhookEnabled)
        _subnetCIDR = State(initialValue: config.wrappedValue.subnetCIDR ?? "")
        _scheduleEnabled = State(initialValue: config.wrappedValue.scheduleEnabled)
        _scheduleIntervalHours = State(initialValue: config.wrappedValue.scheduleIntervalHours)
        _apiEnabled = State(initialValue: config.wrappedValue.apiEnabled)
        _apiPort = State(initialValue: String(config.wrappedValue.apiPort))
        _autoUpdateRules = State(initialValue: config.wrappedValue.autoUpdateRules)
        _rulesURL = State(initialValue: config.wrappedValue.rulesURL)
    }

    var body: some View {
        TabView {
            scanSettingsTab
                .tabItem { Label("Scan", systemImage: "gearshape.2") }

            networkTab
                .tabItem { Label("Network", systemImage: "network") }

            alertsTab
                .tabItem { Label("Alerts", systemImage: "bell") }

            scheduleTab
                .tabItem { Label("Schedule", systemImage: "clock.arrow.circlepath") }

            apiTab
                .tabItem { Label("API", systemImage: "globe") }
        }
        .frame(width: 460, height: 520)
        .padding()
    }

    private var scanSettingsTab: some View {
        Form {
            Section("Port Range (TCP)") {
                HStack {
                    Text("From:").frame(width: 50, alignment: .trailing)
                    TextField("", value: $portFrom, formatter: NumberFormatter()).frame(width: 80)
                    Text("To:")
                    TextField("", value: $portTo, formatter: NumberFormatter()).frame(width: 80)
                }
            }

            Section("Timing") {
                HStack {
                    Text("Timeout (s):").frame(width: 100, alignment: .trailing)
                    TextField("", value: $timeout, formatter: NumberFormatter()).frame(width: 80)
                }
                HStack {
                    Text("Concurrency:").frame(width: 100, alignment: .trailing)
                    TextField("", value: $maxConcurrency, formatter: NumberFormatter()).frame(width: 80)
                }
            }

            Section("Options") {
                Toggle("Service detection", isOn: $serviceDetection)
                Toggle("OS detection", isOn: $osDetection)
            }

            Section("Exclusions") {
                TextField("Exclude IPs (comma-separated)", text: $excludeText)
            }

            Section("Rules Auto-Update") {
                Toggle("Auto-update rules on scan", isOn: $autoUpdateRules)

                TextField("Rules JSON URL", text: $rulesURL)
                    .font(.caption)
                    .textFieldStyle(.roundedBorder)

                if !rulesURL.isEmpty {
                    let version = RuleUpdater.cachedVersion.map { "v\($0)" } ?? "bundled"
                    let lastUpdate = RuleUpdater.lastUpdateDate.map { "Last: \($0.formatted(date: .abbreviated, time: .shortened))" } ?? "Not cached"
                    HStack(spacing: 8) {
                        Circle().fill(RuleUpdater.isCacheStale() ? Color.orange : Color.green).frame(width: 6, height: 6)
                        Text("\(version) — \(lastUpdate)").font(.caption).foregroundStyle(.secondary)
                    }
                }
            }

            HStack {
                Button("Reset Defaults") { applyDefaults() }
                Spacer()
                Button("Done") { saveAndDismiss() }
                    .buttonStyle(.borderedProminent)
            }
        }
        .formStyle(.grouped)
    }

    private var networkTab: some View {
        Form {
            Section("Subnet") {
                TextField("CIDR (e.g. 10.0.0.0/24, leave empty for auto)", text: $subnetCIDR)
            }

            Section("UDP Scan") {
                Toggle("Enable UDP scan", isOn: $scanUDP)
                    .disabled(true)
                Text("UDP scanning slows scans significantly. ⚠️ Experimental.")
                    .font(.caption).foregroundStyle(.secondary)

                if scanUDP {
                    HStack {
                        Text("From:").frame(width: 50, alignment: .trailing)
                        TextField("", value: $udpFrom, formatter: NumberFormatter()).frame(width: 80)
                        Text("To:")
                        TextField("", value: $udpTo, formatter: NumberFormatter()).frame(width: 80)
                    }
                }
            }

            HStack {
                Button("Reset Defaults") { applyDefaults() }
                Spacer()
                Button("Done") { saveAndDismiss() }
                    .buttonStyle(.borderedProminent)
            }
        }
        .formStyle(.grouped)
    }

    private var alertsTab: some View {
        Form {
            Section("Webhook Alerts") {
                Toggle("Send webhook on scan complete", isOn: $webhookEnabled)

                TextField("Webhook URL", text: $webhookURL)
                    .textFieldStyle(.roundedBorder)
                    .disabled(!webhookEnabled)

                Text("Supported: Slack, Discord, or any JSON webhook").font(.caption).foregroundStyle(.secondary)

                if webhookEnabled && !webhookURL.isEmpty {
                    HStack {
                        Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                        Text("Webhook configured").font(.caption)
                    }
                }
            }

            Section("Alert Triggers") {
                Text("Alerts are sent when a scan completes.")
                    .font(.caption).foregroundStyle(.secondary)
                Text("Payload includes device count, open ports, vulnerability summary, and risk score.")
                    .font(.caption).foregroundStyle(.secondary)
            }

            HStack {
                Button("Reset Defaults") { applyDefaults() }
                Spacer()
                Button("Done") { saveAndDismiss() }
                    .buttonStyle(.borderedProminent)
            }
        }
        .formStyle(.grouped)
    }

    private var scheduleTab: some View {
        Form {
            Section("Scheduled Scans") {
                Toggle("Enable scheduled scanning", isOn: $scheduleEnabled)

                if scheduleEnabled {
                    HStack {
                        Text("Interval (hours):").frame(width: 120, alignment: .trailing)
                        TextField("", value: $scheduleIntervalHours, formatter: NumberFormatter())
                            .frame(width: 80)
                        Stepper("", value: $scheduleIntervalHours, in: 1...168, step: 1)
                    }

                    Text("Scans will run every \(Int(scheduleIntervalHours)) hour(s) while the app is open.")
                        .font(.caption).foregroundStyle(.secondary)

                    if scheduleEnabled {
                        HStack {
                            Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                            Text("Next scan: \(nextScanText)")
                                .font(.caption)
                        }
                    }
                }
            }

            Section("Launch Agent (Background)") {
                Text("Install a launchd agent to run scans even when the app is closed.")
                    .font(.caption).foregroundStyle(.secondary)

                HStack(spacing: 12) {
                    Button("Install Launch Agent") {
                        if ScanScheduler.installLaunchAgent(path: Bundle.main.executablePath ?? "", intervalSeconds: Int(scheduleIntervalHours * 3600)) {
                            viewModel.statusMessage = "Launch agent installed"
                        } else {
                            viewModel.errorMessage = "Failed to install launch agent"
                        }
                    }
                    Button("Remove Launch Agent") {
                        _ = ScanScheduler.uninstallLaunchAgent()
                        viewModel.statusMessage = "Launch agent removed"
                    }
                }
            }

            HStack {
                Button("Reset Defaults") { applyDefaults() }
                Spacer()
                Button("Done") { saveAndDismiss() }
                    .buttonStyle(.borderedProminent)
            }
        }
        .formStyle(.grouped)
    }

    // MARK: - API Tab
    private var apiTab: some View {
        Form {
            Section("REST API") {
                Toggle("Enable REST API", isOn: $apiEnabled)

                if apiEnabled {
                    HStack {
                        Text("Port:").frame(width: 50, alignment: .trailing)
                        TextField("8080", text: $apiPort)
                            .frame(width: 80)
                    }

                    let status = RESTServer.shared.isRunning
                    HStack(spacing: 8) {
                        Circle().fill(status ? Color.green : Color.gray).frame(width: 8, height: 8)
                        Text(status ? "Running on port \(apiPort)" : "Stopped")
                            .font(.caption)
                    }

                    Text("Endpoints: /api/v1/devices, /api/v1/scans, /api/v1/health, /api/v1/export/csv, POST /api/v1/scans")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }

            HStack {
                Button("Reset Defaults") { applyDefaults() }
                Spacer()
                Button("Done") { saveAndDismiss() }
                    .buttonStyle(.borderedProminent)
            }
        }
        .formStyle(.grouped)
    }

    private var nextScanText: String {
        guard scheduleEnabled, let next = ScanScheduler.shared.nextScanAt else { return "—" }
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .full
        return formatter.localizedString(for: next, relativeTo: Date())
    }

    private func applyDefaults() {
        let d = ScanConfig.default
        portFrom = d.portRange.lowerBound; portTo = d.portRange.upperBound
        udpFrom = d.udpPortRange.lowerBound; udpTo = d.udpPortRange.upperBound
        timeout = d.timeout; maxConcurrency = d.maxConcurrency
        excludeText = ""; serviceDetection = d.serviceDetection; osDetection = d.osDetection
        scanUDP = d.scanUDP; webhookURL = d.webhookURL; webhookEnabled = d.webhookEnabled
        subnetCIDR = d.subnetCIDR ?? ""
        scheduleEnabled = d.scheduleEnabled; scheduleIntervalHours = d.scheduleIntervalHours
        apiEnabled = d.apiEnabled; apiPort = String(d.apiPort)
        autoUpdateRules = d.autoUpdateRules; rulesURL = d.rulesURL
    }

    private func saveAndDismiss() {
        config.portRange = portFrom...portTo
        config.udpPortRange = udpFrom...udpTo
        config.timeout = timeout
        config.maxConcurrency = maxConcurrency
        config.excludeIPs = excludeText.split(separator: ",").map(String.init).map { $0.trimmingCharacters(in: .whitespaces) }
        config.serviceDetection = serviceDetection
        config.osDetection = osDetection
        config.scanUDP = scanUDP
        config.webhookURL = webhookURL
        config.webhookEnabled = webhookEnabled
        config.subnetCIDR = subnetCIDR.isEmpty ? nil : subnetCIDR
        config.scheduleEnabled = scheduleEnabled
        config.scheduleIntervalHours = scheduleIntervalHours
        viewModel.updateSchedule(enabled: scheduleEnabled, intervalHours: scheduleIntervalHours)
        viewModel.updateAPI(enabled: apiEnabled, port: Int(apiPort) ?? 8080)
        config.autoUpdateRules = autoUpdateRules
        config.rulesURL = rulesURL
        dismiss()
    }
}

// MARK: - Keyboard Shortcuts
private struct KeyboardShortcutHandling: ViewModifier {
    let viewModel: ScannerViewModel

    func body(content: Content) -> some View {
        content
            .background {
                Button("") { viewModel.startScan() }
                    .keyboardShortcut("r", modifiers: .command).hidden()
                    .disabled(viewModel.isScanning)

                Button("") { viewModel.showConfig = true }
                    .keyboardShortcut(",", modifiers: .command).hidden()
            }
    }
}

private extension View {
    func keyboardShortcutHandling(viewModel: ScannerViewModel) -> some View {
        modifier(KeyboardShortcutHandling(viewModel: viewModel))
    }
}
