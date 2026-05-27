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
        .alert("Error", isPresented: .init(
            get: { viewModel.errorMessage != nil },
            set: { if !$0 { viewModel.errorMessage = nil } }
        )) {
            Button("OK") { viewModel.errorMessage = nil }
        } message: {
            Text(viewModel.errorMessage ?? "")
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

            Picker("Scan source", selection: .init(
                get: { viewModel.selectedHistoryScanID == nil ? "current" : "history" },
                set: { if $0 == "current" { viewModel.selectedHistoryScanID = nil } }
            )) {
                Text("Current Scan").tag("current")
                Text("History (\(viewModel.history.count))").tag("history")
            }
            .pickerStyle(.segmented)
            .padding(.horizontal, 8)
            .padding(.bottom, 4)
            .labelsHidden()

            Divider()

            let sourceDevices = viewModel.selectedHistoryScanID != nil ? viewModel.historyDevices : viewModel.devices

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

    private var searchBar: some View {
        HStack {
            Image(systemName: "magnifyingglass")
                .foregroundStyle(.secondary)
            TextField("Filter by IP or hostname\u{2026}", text: $viewModel.searchText)
                .textFieldStyle(.roundedBorder)
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
        .accessibilityLabel("Search devices by IP or hostname")
        .focusable()
    }

    // MARK: - Dashboard
    private var lastScanSubtitle: String {
        if let first = viewModel.history.first {
            let ago = RelativeDateTimeFormatter()
            ago.unitsStyle = .abbreviated
            return "Last scan: \(ago.localizedString(for: first.timestamp, relativeTo: Date()))"
        }
        if !viewModel.devices.isEmpty {
            return "Current session scan (not yet saved)"
        }
        return ""
    }

    private var dashboard: some View {
        ScrollView {
            VStack(spacing: 24) {
                if viewModel.isScanning {
                    scanningOverlay
                } else if viewModel.devices.isEmpty && viewModel.selectedHistoryScanID == nil {
                    emptyState
                } else {
                    let sourceDevices = viewModel.selectedHistoryScanID != nil ? viewModel.historyDevices : viewModel.devices
                    if !lastScanSubtitle.isEmpty {
                        HStack {
                            Label(lastScanSubtitle, systemImage: "clock")
                                .font(.caption).foregroundStyle(.tertiary)
                            Spacer()
                        }
                    }
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
        .animation(.smooth(duration: 0.3), value: viewModel.devices.count)
        .animation(.smooth(duration: 0.3), value: viewModel.selectedHistoryScanID)
        .animation(.easeInOut(duration: 0.25), value: viewModel.activeComplianceFilters)
    }

    private var scanningOverlay: some View {
        VStack(spacing: 20) {
            ProgressView()
                .progressViewStyle(.circular)
                .controlSize(.large)
                .scaleEffect(1.2)
            Text("Scanning...")
                .font(.title2).bold()
            Text(viewModel.statusMessage)
                .font(.subheadline)
                .foregroundStyle(.secondary)
            if viewModel.progress > 0 {
                ProgressView(value: viewModel.progress)
                    .frame(width: 200)
                Text("\(Int(viewModel.progress * 100))%")
                    .font(.caption).foregroundStyle(.tertiary)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
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
        let maxRisk = devices.map(\.riskScore).max() ?? 0

        return LazyVGrid(columns: [GridItem(.adaptive(minimum: 160))], spacing: 16) {
            StatCard(title: "Devices", value: "\(devices.count)", icon: "desktopcomputer", color: .blue)
            StatCard(title: "Open Ports", value: "\(totalOpen)", icon: "door.left.hand.open", color: .orange)
            StatCard(title: "Vulnerabilities", value: "\(totalVulns)", icon: "exclamationmark.triangle", color: .red)
            StatCard(title: "Max Risk", value: String(format: "%.1f", maxRisk), icon: "gauge.medium", color: riskColor(maxRisk))
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
                        .clipShape(.rect(cornerRadius: 6))
                        .overlay(
                            RoundedRectangle(cornerRadius: 6).stroke(isActive ? Color.accentColor : Color.gray.opacity(0.3), lineWidth: 1)
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
                .accessibilityLabel("Vulnerability severity distribution chart showing counts of critical, high, medium, low, and info findings")
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
                                    Text("\(summary.deviceCount) devices \u{00B7} \(summary.totalVulnerabilities) vulns \u{00B7} \(String(format: "%.1f", summary.riskScore)) risk")
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
                            Text("\u{00D7} \(cve.count)").font(.caption).foregroundStyle(.secondary)
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
            Text("Open Ports (\(tcpOpen + udpOpen) \u{2014} TCP:\(tcpOpen) UDP:\(udpOpen))")
                .font(.headline)

            if device.ports.isEmpty {
                Text("Port scan data not available")
                    .foregroundStyle(.secondary).font(.subheadline)
            } else {
                Table(device.ports.filter { $0.state == .open }.sorted()) {
                    TableColumn("Port") { port in Text("\(port.number)") }
                    TableColumn("Protocol") { port in
                        Text(port.transport.rawValue)
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    TableColumn("State") { port in Text(port.state.rawValue.capitalized) }
                    TableColumn("Service") { port in Text(port.service ?? "\u{2013}") }
                    TableColumn("Banner") { port in
                        Text(port.banner ?? "\u{2013}").lineLimit(1).truncationMode(.tail)
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
            if viewModel.isScanning {
                HStack {
                    ProgressView().progressViewStyle(.linear).frame(width: 100)
                    Button("Stop", action: { viewModel.stopScan() })
                        .accessibilityLabel("Stop current scan")
                }
            } else {
                Button(action: { viewModel.startScan() }) {
                    Label("Start Scan", systemImage: "play.fill")
                }
                .help("Start Scan (\u{2318}R)")
                .accessibilityLabel("Start network scan")
            }
        }

        ToolbarItem(placement: .automatic) {
            Button(action: { showTopology = true }) {
                Label("Topology Map", systemImage: "point.3.connected.trianglepath.dotted")
            }
            .help("Network Topology Map")
            .disabled(viewModel.devices.isEmpty && viewModel.selectedHistoryScanID == nil)
            .accessibilityLabel("Show network topology map")
        }

        ToolbarItem(placement: .automatic) {
            Button(action: { viewModel.showRulesManager = true }) {
                Label("Custom Rules", systemImage: "doc.badge.gearshape")
            }
            .help("Manage Custom Rules")
            .accessibilityLabel("Manage custom vulnerability rules")
        }

        if !viewModel.config.rulesURL.isEmpty {
            ToolbarItem(placement: .automatic) {
                Button(action: { viewModel.updateRules() }) {
                    Label("Update Rules", systemImage: "arrow.down.circle")
                }
                .disabled(viewModel.isUpdatingRules)
                .help("Fetch latest rules")
                .accessibilityLabel("Update vulnerability rules from remote")
            }
        }

        ToolbarItem(placement: .automatic) {
            Button(action: { viewModel.showConfig = true }) {
                Label("Configure", systemImage: "gearshape")
            }
            .help("Scan Settings (\u{2318},)")
            .accessibilityLabel("Open scan settings")
        }

        ToolbarItem(placement: .automatic) {
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
            .accessibilityLabel("Export scan results")
        }

        ToolbarItem(placement: .status) {
            HStack(spacing: 6) {
                Circle()
                    .fill(statusColor)
                    .frame(width: 7, height: 7)
                Text(viewModel.statusMessage)
                    .font(.caption)
                    .lineLimit(1)

                if viewModel.isUpdatingRules {
                    ProgressView()
                        .progressViewStyle(.circular)
                        .controlSize(.small)
                        .scaleEffect(0.5)
                }

                if viewModel.rulesVersion > 0, !viewModel.isScanning {
                    Text("v\(viewModel.rulesVersion)")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                    if RuleUpdater.isCacheStale() {
                        Image(systemName: "clock.arrow.circlepath")
                            .font(.caption2)
                            .foregroundStyle(.orange)
                    }
                }

                if viewModel.peakMemoryMB > 100 {
                    Text("\(String(format: "%.0f", viewModel.peakMemoryMB)) MB")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
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
                do {
                    try html.write(to: url, atomically: true, encoding: .utf8)
                    Logger.ui.info("HTML report exported to \(url.path)")
                } catch {
                    viewModel.errorMessage = "Failed to export HTML: \(error.localizedDescription)"
                }
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
                do {
                    try csv.write(to: url, atomically: true, encoding: .utf8)
                    Logger.ui.info("CSV exported to \(url.path)")
                } catch {
                    viewModel.errorMessage = "Failed to export CSV: \(error.localizedDescription)"
                }
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
                do {
                    try json.write(to: url, atomically: true, encoding: .utf8)
                    Logger.ui.info("JSON exported to \(url.path)")
                } catch {
                    viewModel.errorMessage = "Failed to export JSON: \(error.localizedDescription)"
                }
            }
        }
    }

    private var statusColor: Color {
        if viewModel.isScanning { return .orange }
        if viewModel.isUpdatingRules { return .orange }
        if viewModel.devices.isEmpty && viewModel.historyDevices.isEmpty { return .gray }
        if viewModel.devices.contains(where: { $0.vulnerabilities.contains(where: { $0.severity >= 9 }) }) { return .red }
        if viewModel.devices.contains(where: { $0.vulnerabilities.contains(where: { $0.severity >= 7 }) }) { return .orange }
        return .green
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
        .frame(minWidth: 400, idealWidth: 500, minHeight: 400, idealHeight: 520)
        .onExitCommand { showTopology = false }
    }
}

// MARK: - Keyboard Shortcuts
private struct KeyboardShortcutHandling: ViewModifier {
    let viewModel: ScannerViewModel
    @FocusState private var isSearchFocused: Bool
    @State private var exportMenuPresented = false

    func body(content: Content) -> some View {
        content
            .background {
                Button("") { viewModel.startScan() }
                    .keyboardShortcut("r", modifiers: .command).hidden()
                    .disabled(viewModel.isScanning)

                Button("") { viewModel.stopScan() }
                    .keyboardShortcut(".", modifiers: .command).hidden()
                    .disabled(!viewModel.isScanning)

                Button("") { viewModel.showConfig = true }
                    .keyboardShortcut(",", modifiers: .command).hidden()

                Button("") { isSearchFocused = true }
                    .keyboardShortcut("f", modifiers: .command).hidden()

                Button("") { exportMenuPresented = true }
                    .keyboardShortcut("e", modifiers: [.command, .shift]).hidden()
            }
    }
}

private extension View {
    func keyboardShortcutHandling(viewModel: ScannerViewModel) -> some View {
        modifier(KeyboardShortcutHandling(viewModel: viewModel))
    }
}
