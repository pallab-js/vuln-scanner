import SwiftUI
import Charts
import UniformTypeIdentifiers
import Core
import API
import Engine

public struct ContentView: View {
    @State private var viewModel = ScannerViewModel()
    @State private var showTopology = false
    @State private var sidebarWidth: CGFloat = 280
    @State private var showComplianceBar = false
    @State private var vulnDisplayLimit = 100

    public init() {}

    public var body: some View {
        Group {
            if !viewModel.isAuthenticated && viewModel.needsAuth {
                authView
            } else {
                mainContent
            }
        }
        .onAppear { authenticateIfNeeded() }
    }

    // MARK: - Auth (Tier 3.18)
    private func authenticateIfNeeded() {
        Task {
            let result = await AuthManager.shared.authenticate()
            switch result {
            case .authenticated(let role):
                viewModel.isAuthenticated = true
                viewModel.userRole = role
            case .unauthenticated:
                viewModel.needsAuth = AuthManager.shared.currentRole == .admin
                viewModel.isAuthenticated = !viewModel.needsAuth
            }
        }
    }

    private var authView: some View {
        VStack(spacing: 20) {
            Image(systemName: "lock.shield")
                .font(.system(size: 56))
                .foregroundStyle(.tint)
            Text("LAN Scanner")
                .font(.largeTitle).bold()
            Text("Authenticate with Touch ID to continue")
                .foregroundStyle(.secondary)
            Button("Authenticate") { authenticateIfNeeded() }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - Main Content
    private var mainContent: some View {
        NavigationSplitView {
            sidebar
                .navigationSplitViewColumnWidth(min: 240, ideal: sidebarWidth, max: 360)
        } detail: {
            if let device = viewModel.selectedDevice {
                deviceDetail(device: device)
            } else {
                dashboard
            }
        }
        .toolbar { toolbarContent }
        .frame(minWidth: 1024, minHeight: 700)
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
        .sheet(isPresented: $viewModel.showCompareView) {
            ScanCompareView(
                currentDevices: viewModel.sourceDevices,
                history: viewModel.history,
                loadDevices: { scanID in try? ScanStore.shared.loadDevices(scanID: scanID) }
            )
        }
        .sheet(isPresented: $viewModel.showExportPreview) {
            ExportPreviewView(content: viewModel.exportPreviewContent, format: viewModel.exportPreviewFormat) {
                viewModel.exportSaveAction?()
                viewModel.showToast(message: "Export saved")
            }
        }
        .sheet(isPresented: $viewModel.showAuditLog) {
            auditLogSheet
        }
        .sheet(isPresented: $viewModel.showProfiles) {
            profileSheet
        }
        .toast(isPresented: $viewModel.isShowingToast, message: viewModel.toastMessage ?? "", icon: viewModel.toastIcon, color: viewModel.toastColor)
        .background {
            Button("") { viewModel.startScan() }
                .keyboardShortcut("r", modifiers: .command).hidden()
                .disabled(viewModel.isScanning || !AuthManager.shared.requireRole(.operator_))
            Button("") { viewModel.stopScan() }
                .keyboardShortcut(".", modifiers: .command).hidden()
                .disabled(!viewModel.isScanning)
            Button("") { viewModel.showConfig = true }
                .keyboardShortcut(",", modifiers: .command).hidden()
            Button("") { isSearchFocused = true }
                .keyboardShortcut("f", modifiers: .command).hidden()
        }
    }

    // MARK: - Sidebar (Tiers 1.1, 1.2, 1.6, 2.12)
    private var sidebar: some View {
        VStack(spacing: 0) {
            searchBar
                .padding(.horizontal, 8)
                .padding(.vertical, 6)

            Picker("Scan source", selection: $viewModel.scanSource) {
                ForEach(ScannerViewModel.ScanSource.allCases, id: \.self) { source in
                    Text(source.rawValue).tag(source)
                }
            }
            .pickerStyle(.segmented)
            .padding(.horizontal, 8)
            .padding(.bottom, 4)
            .labelsHidden()
            .onChange(of: viewModel.scanSource) { _, newValue in
                if newValue == .current {
                    viewModel.selectedHistoryScanID = nil
                    viewModel.historyDevices = []
                }
            }

            if viewModel.scanSource == .history {
                historyPicker
            }

            Divider()

            tagFilterBar

            if viewModel.isScanning && viewModel.sourceDevices.isEmpty {
                skeletonList
            } else if !viewModel.sourceDevices.isEmpty || viewModel.isScanning {
                deviceList
            } else {
                emptySidebarList
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var emptySidebarList: some View {
        VStack(spacing: 12) {
            Spacer()
            Image(systemName: "magnifyingglass.circle")
                .font(.system(size: 32))
                .foregroundStyle(.tertiary)
            Text("No devices yet")
                .font(.headline)
                .foregroundStyle(.secondary)
            Text("Run a scan to discover devices on your network")
                .font(.caption)
                .foregroundStyle(.tertiary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)
            Button("Start Scan") {
                viewModel.startScan()
            }
            .buttonStyle(BorderedProminentButtonStyle())
            .controlSize(.small)
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var historyPicker: some View {
        Picker("Select scan", selection: Binding(
            get: { viewModel.selectedHistoryScanID ?? "" },
            set: { if !$0.isEmpty { viewModel.selectHistoryScan(scanID: $0) } }
        )) {
            Text("Choose a scan...").tag("")
            ForEach(viewModel.history) { summary in
                Text(summary.timestamp.formatted(date: .abbreviated, time: .shortened)).tag(summary.scanID)
            }
        }
        .pickerStyle(.menu)
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
    }

    private var skeletonList: some View {
        List {
            ForEach(0..<8, id: \.self) { _ in
                SkeletonRow()
            }
            .listRowSeparator(.hidden)
        }
        .listStyle(.sidebar)
        .frame(minWidth: 250)
    }

    // MARK: - Search (Tier 1.6)
    @FocusState private var isSearchFocused: Bool

    private var searchBar: some View {
        HStack(spacing: 4) {
            Image(systemName: "magnifyingglass")
                .foregroundStyle(.secondary)
                .imageScale(.small)
            TextField("Filter by IP or hostname\u{2026}", text: $viewModel.searchText)
                .textFieldStyle(.plain)
                .font(.subheadline)
                .focused($isSearchFocused)
            if !viewModel.searchText.isEmpty {
                Button {
                    viewModel.searchText = ""
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundStyle(.tertiary)
                        .imageScale(.small)
                }
                .buttonStyle(.plain)
            }
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 5)
        .background(.surfaceSecondary)
        .clipShape(RoundedRectangle(cornerRadius: 6))
        .overlay(
            RoundedRectangle(cornerRadius: 6)
                .stroke(isSearchFocused ? Color.accentColor : Color.clear, lineWidth: 1.5)
        )
        .accessibilityLabel("Search devices by IP or hostname")
    }

    // MARK: - Tag Filter (Tier 2.13)
    private var tagFilterBar: some View {
        let tags = viewModel.allKnownTags
        return Group {
            if !tags.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 4) {
                            FilterChip(
                                label: "All",
                                isSelected: viewModel.tagFilter == nil,
                                color: .gray
                            ) { viewModel.tagFilter = nil }

                            ForEach(tags) { tag in
                                FilterChip(
                                    label: tag.name,
                                    isSelected: viewModel.tagFilter == tag.name,
                                    color: tagColor(tag.color)
                                ) {
                                    viewModel.tagFilter = viewModel.tagFilter == tag.name ? nil : tag.name
                                }
                            }
                        }
                        .padding(.horizontal, 8)
                    }
                }
                .padding(.vertical, 4)
            }
        }
    }

    // MARK: - Device List (Tier 2.12)
    private var deviceList: some View {
        List(selection: $viewModel.selectedDevice) {
            let displayDevices = viewModel.tagFilter != nil ? viewModel.filteredDevicesWithTags : viewModel.filteredDevices
            ForEach(displayDevices) { device in
                DeviceRow(device: device, tags: viewModel.deviceTags[device.ip] ?? [])
                    .tag(device)
                    .transition(.slide)
                    .contextMenu {
                        Menu("Add Tag") {
                            ForEach(viewModel.allKnownTags) { tag in
                                Button(tag.name) { viewModel.addTag(tag.name, color: tag.color, to: device.ip) }
                            }
                        }
                        if !viewModel.multiSelectedIPs.isEmpty {
                            Button("Add to selection") { viewModel.multiSelectedIPs.insert(device.ip) }
                        }
                        Divider()
                        Button("Copy IP") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(device.ip, forType: .string)
                        }
                    }
            }
        }
        .listStyle(.sidebar)
        .frame(minWidth: 250)
        .animation(.easeInOut(duration: 0.3), value: viewModel.sourceDevices.count)
        .animation(.easeInOut(duration: 0.3), value: viewModel.tagFilter)
    }

    // MARK: - Dashboard (Tier 2.9: Tabbed)
    private var dashboard: some View {
        VStack(spacing: 0) {
            if viewModel.isViewingHistory {
                HStack {
                    Label("Viewing history scan", systemImage: "clock.arrow.circlepath")
                        .font(.caption).foregroundStyle(.secondary)
                    Button("Back to current") { viewModel.switchToCurrentScan() }
                        .buttonStyle(.plain).font(.caption).foregroundStyle(Color.accentColor)
                    Spacer()
                }
                .padding(.horizontal, 24)
                .padding(.top, 12)
            }

            if viewModel.isScanning && viewModel.sourceDevices.isEmpty {
                scanningView
            } else if viewModel.sourceDevices.isEmpty && !viewModel.isViewingHistory {
                EmptyStateView(
                    icon: "network.slash",
                    title: "No scan results",
                    message: "Configure scan settings, then hit Start Scan",
                    actions: [
                        EmptyStateAction(label: "Configure", icon: "gearshape", action: { viewModel.showConfig = true }),
                        EmptyStateAction(label: "Start Scan", icon: "play.fill", primary: true, action: { viewModel.startScan() }),
                    ]
                )
            } else {
                dashboardTabs
            }
        }
        .animation(.smooth(duration: 0.3), value: viewModel.sourceDevices.count)
        .animation(.smooth(duration: 0.3), value: viewModel.isViewingHistory)
        .animation(.easeInOut(duration: 0.25), value: viewModel.activeComplianceFilters)
    }

    // MARK: - Scanning View (Tier 1.2)
    private var scanningView: some View {
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

    // MARK: - Dashboard Tabs
    private var dashboardTabs: some View {
        VStack(spacing: 0) {
            Picker("Dashboard Tab", selection: $dashboardTab) {
                Label("Overview", systemImage: "rectangle.grid.1x2").tag(DashboardTab.overview)
                Label("Devices", systemImage: "desktopcomputer").tag(DashboardTab.devices)
                Label("Vulnerabilities", systemImage: "exclamationmark.triangle").tag(DashboardTab.vulns)
                Label("Compliance", systemImage: "checklist").tag(DashboardTab.compliance)
                Label("History", systemImage: "clock.arrow.circlepath").tag(DashboardTab.history)
            }
            .pickerStyle(.segmented)
            .padding(.horizontal, 24)
            .padding(.vertical, 8)

            Divider()

            ScrollView {
                Group {
                    switch dashboardTab {
                    case .overview: overviewTab
                    case .devices: devicesTab
                    case .vulns: vulnsTab
                    case .compliance: complianceTab
                    case .history: historyTab
                    }
                }
                .padding(24)
            }
        }
    }

    @State private var dashboardTab: DashboardTab = .overview

    private enum DashboardTab: String, CaseIterable {
        case overview = "Overview"
        case devices = "Devices"
        case vulns = "Vulnerabilities"
        case compliance = "Compliance"
        case history = "History"
    }

    // MARK: - Overview Tab
    private var overviewTab: some View {
        VStack(spacing: 24) {
            let source = viewModel.sourceDevices
            if !lastScanSubtitle.isEmpty {
                HStack {
                    Label(lastScanSubtitle, systemImage: "clock")
                        .font(.caption).foregroundStyle(.tertiary)
                    Spacer()
                }
            }
            summaryCards(devices: source)
            complianceFilterBar
            severityChart(devices: source, compliance: viewModel.activeComplianceFilters)
            recentDevices(devices: source)
            trendSection
        }
    }

    private var lastScanSubtitle: String {
        if viewModel.isViewingHistory {
            if let first = viewModel.history.first(where: { $0.scanID == viewModel.selectedHistoryScanID }) {
                let ago = RelativeDateTimeFormatter()
                ago.unitsStyle = .abbreviated
                return "Scan from: \(ago.localizedString(for: first.timestamp, relativeTo: Date()))"
            }
        }
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

    // MARK: - Devices Tab (Tier 2.11, 2.12)
    private var devicesTab: some View {
        let source = viewModel.sourceDevices
        let sorted = source.sorted { $0.riskScore > $1.riskScore }
        return VStack(alignment: .leading, spacing: 12) {
            Text("All Devices (\(source.count))")
                .font(.headline)

            if let severity = viewModel.selectedSeverityFilter {
                HStack {
                    Label("Filtered: \(severity.rawValue.capitalized) severity", systemImage: "line.3.horizontal.decrease.circle.fill")
                        .font(.caption).foregroundStyle(.secondary)
                    Button("Clear") { viewModel.selectedSeverityFilter = nil }
                        .buttonStyle(.plain).font(.caption).foregroundStyle(Color.accentColor)
                }
            }

            LazyVStack(spacing: 6) {
                ForEach(sorted) { device in
                    DeviceDetailRow(device: device, tags: viewModel.deviceTags[device.ip] ?? [])
                        .onTapGesture { viewModel.selectedDevice = device }
                }
            }
        }
    }

    // MARK: - Vulns Tab
    private var vulnsTab: some View {
        let allVulns = viewModel.sourceDevices.flatMap(\.vulnerabilities).sorted()
        return VStack(alignment: .leading, spacing: 12) {
            Text("All Vulnerabilities (\(allVulns.count))")
                .font(.headline)

            if allVulns.isEmpty {
                EmptyStateView(icon: "checkmark.shield", title: "No vulnerabilities", message: "No vulnerabilities detected across scanned devices")
            } else {
                LazyVStack(spacing: 6) {
                    ForEach(allVulns.prefix(vulnDisplayLimit)) { vuln in
                        VulnRowMini(vuln: vuln)
                    }
                    if allVulns.count > vulnDisplayLimit {
                        HStack(spacing: 6) {
                            Text("Showing \(vulnDisplayLimit) of \(allVulns.count) vulnerabilities")
                                .font(.caption).foregroundStyle(.secondary)
                            Button("Show All") { vulnDisplayLimit = Int.max }
                                .font(.caption).buttonStyle(.plain).foregroundStyle(Color.accentColor)
                        }
                    }
                }
            }
        }
    }

    // MARK: - Compliance Tab
    private var complianceTab: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Compliance Mapping").font(.headline)

            let frameworks = ComplianceFramework.allCases
            ForEach(frameworks, id: \.self) { fw in
                let related = viewModel.sourceDevices.flatMap(\.vulnerabilities).filter { $0.compliance.contains(fw) }
                if !related.isEmpty {
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Circle().fill(frameworkColor(fw)).frame(width: 8, height: 8)
                            Text(fw.rawValue).font(.body).bold()
                            Spacer()
                            Text("\(related.count) findings").font(.caption).foregroundStyle(.secondary)
                        }
                        let unique = Set(related.map(\.id)).sorted()
                        Text(unique.joined(separator: ", "))
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    .padding()
                    .background(.surfacePrimary)
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                    .overlay(RoundedRectangle(cornerRadius: 8).stroke(.borderStandard, lineWidth: 1))
                }
            }
        }
    }

    // MARK: - History Tab (Tier 1.4)
    private var historyTab: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Scan History (\(viewModel.history.count))")
                .font(.headline)

            if viewModel.history.isEmpty {
                EmptyStateView(icon: "clock.arrow.circlepath", title: "No history", message: "Run a scan to populate history")
            } else {
                LazyVStack(spacing: 8) {
                    ForEach(viewModel.history.prefix(viewModel.historyLoadCount)) { summary in
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
                                riskBadge(score: summary.riskScore)
                            }
                            .padding(.vertical, 2)
                        }
                        .buttonStyle(.plain)
                        .contextMenu {
                            Button("Load scan") { viewModel.selectHistoryScan(scanID: summary.scanID) }
                            if viewModel.userRole.canDeleteHistory {
                                Divider()
                                Button("Delete scan", role: .destructive) { viewModel.deleteHistoryScan(scanID: summary.scanID) }
                            }
                        }
                    }

                    if viewModel.history.count > viewModel.historyLoadCount {
                        HStack(spacing: 6) {
                            if viewModel.isLoadingMoreHistory {
                                ProgressView().controlSize(.small).scaleEffect(0.7)
                            }
                            Button("Show More (\(viewModel.history.count - viewModel.historyLoadCount) remaining)") {
                                viewModel.loadMoreHistory()
                            }
                            .font(.caption).buttonStyle(.bordered).frame(maxWidth: .infinity)
                            .disabled(viewModel.isLoadingMoreHistory)
                        }
                    }
                }
            }
        }
    }

    // MARK: - Summary Cards (Tier 4.28: shadows)
    private func summaryCards(devices: [Device]) -> some View {
        let totalOpen = devices.reduce(0) { $0 + $1.ports.filter { $0.state == .open }.count }
        let totalVulns = devices.reduce(0) { $0 + $1.vulnerabilities.count }
        let maxRisk = devices.map(\.riskScore).max() ?? 0

        return LazyVGrid(columns: [GridItem(.adaptive(minimum: 150))], spacing: 16) {
            StatCard(title: "Devices", value: "\(devices.count)", icon: "desktopcomputer", color: .blue)
            StatCard(title: "Open Ports", value: "\(totalOpen)", icon: "door.left.hand.open", color: .orange)
            StatCard(title: "Vulnerabilities", value: "\(totalVulns)", icon: "exclamationmark.triangle", color: .red)
            StatCard(title: "Max Risk", value: String(format: "%.1f", maxRisk), icon: "gauge.medium", color: riskColor(maxRisk))
            StatCard(title: "Duration", value: String(format: "%.1fs", viewModel.scanDuration), icon: "clock", color: .purple)
        }
    }

    // MARK: - Compliance Filter (collapsible)
    private var complianceFilterBar: some View {
        let hasComplianceVulns = viewModel.sourceDevices.contains(where: { $0.vulnerabilities.contains(where: { !$0.compliance.isEmpty }) })
        let hasActiveFilters = !viewModel.activeComplianceFilters.isEmpty

        return Group {
            if hasActiveFilters || hasComplianceVulns {
                if hasActiveFilters || showComplianceBar {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text("Compliance Filter").font(.caption).foregroundStyle(.secondary)
                            Spacer()
                            if !hasActiveFilters {
                                Button("Hide") { showComplianceBar = false }
                                    .font(.caption2).foregroundStyle(.secondary).buttonStyle(.plain)
                            }
                        }
                        HStack(spacing: 8) {
                            ForEach(ComplianceFramework.allCases, id: \.self) { framework in
                                FilterChip(
                                    label: framework.rawValue,
                                    isSelected: viewModel.activeComplianceFilters.contains(framework),
                                    color: frameworkColor(framework)
                                ) {
                                    if viewModel.activeComplianceFilters.contains(framework) {
                                        viewModel.activeComplianceFilters.remove(framework)
                                    } else {
                                        viewModel.activeComplianceFilters.insert(framework)
                                    }
                                }
                            }
                            if !viewModel.activeComplianceFilters.isEmpty {
                                Button("Clear") { viewModel.activeComplianceFilters.removeAll() }
                                    .font(.caption2).foregroundStyle(.secondary)
                                    .buttonStyle(.plain)
                            }
                        }
                    }
                    .padding()
                    .background(.surfacePrimary)
                    .clipShape(RoundedRectangle(cornerRadius: 10))
                    .overlay(RoundedRectangle(cornerRadius: 10).stroke(.borderStandard, lineWidth: 1))
                } else {
                    Button {
                        showComplianceBar = true
                    } label: {
                        HStack(spacing: 4) {
                            Image(systemName: "line.3.horizontal.decrease.circle").font(.caption)
                            Text("Compliance Filter").font(.caption)
                        }
                        .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.plain)
                    .help("Filter vulnerabilities by compliance framework")
                }
            }
        }
    }

    // MARK: - Severity Chart (Tier 2.11)
    private func severityChart(devices: [Device], compliance: Set<ComplianceFramework> = []) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Vulnerability Severity Distribution")
                    .font(.headline)
                if !compliance.isEmpty {
                    Text("(filtered)")
                        .font(.caption).foregroundStyle(Color.accentColor)
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(Color.accentColor.opacity(0.1))
                        .clipShape(RoundedRectangle(cornerRadius: 4))
                }
            }

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
                .chartOverlay { proxy in
                    GeometryReader { geometry in
                        Rectangle().fill(.clear).contentShape(Rectangle())
                            .onTapGesture { location in
                                guard let plotFrame = proxy.plotFrame else { return }
                                let x = location.x - geometry[plotFrame].origin.x
                                guard x >= 0 else { return }
                                if let key: String = proxy.value(atX: x, as: String.self) {
                                    let keyStr = key
                                    if let level = SeverityLevel.allCases.first(where: { $0.rawValue.capitalized == keyStr }) {
                                        viewModel.toggleSeverityFilter(level)
                                    }
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
        .background(.surfacePrimary)
        .clipShape(RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(.borderStandard, lineWidth: 1))
    }

    // MARK: - Recent Devices
    private func recentDevices(devices: [Device]) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Devices by Risk").font(.headline)

            let sorted = devices.sorted { $0.riskScore > $1.riskScore }
            if sorted.isEmpty {
                Text("No devices found").foregroundStyle(.secondary).font(.subheadline)
            } else {
                ForEach(sorted.prefix(5)) { device in
                    HStack {
                        riskSymbol(device.riskScore)
                            .font(.system(size: 8))
                            .foregroundStyle(riskColor(device.riskScore))
                        Text(device.host ?? device.ip).font(.body)
                        Spacer()
                        HStack(spacing: 4) {
                            Text("\(device.ports.filter { $0.state == .open }.count) ports")
                                .font(.caption).foregroundStyle(.secondary)
                            Text("\(device.vulnerabilities.count) vulns")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        riskBadge(score: device.riskScore)
                    }
                    .padding(.vertical, 4)
                }
            }
        }
        .padding()
        .background(.surfacePrimary)
        .clipShape(RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(.borderStandard, lineWidth: 1))
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
        .background(.surfacePrimary)
        .clipShape(RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(.borderStandard, lineWidth: 1))
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
                riskBadgeText(device.riskScore)
                    .font(.caption2).bold().foregroundStyle(.white)
                    .padding(.horizontal, 4).padding(.vertical, 1)
                    .background(riskColor(device.riskScore))
                    .clipShape(RoundedRectangle(cornerRadius: 3))
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

    // MARK: - Tags (device detail)
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
        .background(.surfacePrimary)
        .clipShape(RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(.borderStandard, lineWidth: 1))
        .sheet(isPresented: $viewModel.showTagEditor) {
            if let ip = viewModel.editingTagDevice {
                TagEditorView(viewModel: viewModel, deviceIP: ip)
            }
        }
    }

    // MARK: - Port Section (Tier 1.5: LazyVStack)
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

    // MARK: - Vuln Section (Tier 1.5: LazyVStack)
    private func vulnSection(device: Device, limit: Int = 100) -> some View {
        let vulns = device.vulnerabilities.sorted()
        return VStack(alignment: .leading, spacing: 8) {
            Text("Vulnerabilities (\(vulns.count)")
                .font(.headline)

            if vulns.isEmpty {
                Text("No vulnerabilities detected").foregroundStyle(.secondary)
            } else {
                LazyVStack(spacing: 6) {
                    ForEach(vulns.prefix(limit)) { vuln in
                        VulnRow(vuln: vuln)
                    }
                    if vulns.count > limit {
                        Text("Showing \(limit) of \(vulns.count) vulnerabilities")
                            .font(.caption).foregroundStyle(.tertiary)
                            .padding(.top, 4)
                    }
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
                .disabled(!AuthManager.shared.requireRole(.operator_))
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
                Button(action: showExportHTML) { Label("Export HTML Report", systemImage: "doc.text") }
                Divider()
                Button(action: showExportCSV) { Label("Export as CSV", systemImage: "tablecells") }
                Button(action: showExportJSON) { Label("Export as JSON", systemImage: "curlybraces") }
                Divider()
                Menu("SIEM Export") {
                    Button("CEF") { showExportSIEM(.cef) }
                    Button("LEEF") { showExportSIEM(.leef) }
                    Button("Syslog") { showExportSIEM(.syslog) }
                    Button("Raw JSON") { showExportSIEM(.rawJSON) }
                }
                if viewModel.userRole == .admin {
                    Divider()
                    Button(action: { viewModel.showAuditLog = true }) { Label("Audit Log", systemImage: "list.bullet.clipboard") }
                    Button(action: { viewModel.showProfiles = true }) { Label("Profiles", systemImage: "square.3.layers.3d") }
                }
            } label: {
                Label("Export", systemImage: "square.and.arrow.down")
            }
            .disabled(viewModel.sourceDevices.isEmpty)
            .help("Export Results")
            .accessibilityLabel("Export scan results")
        }

        ToolbarItem(placement: .automatic) {
            Menu {
                Button(action: { showTopology = true }) {
                    Label("Topology Map", systemImage: "point.3.connected.trianglepath.dotted")
                }
                .disabled(viewModel.sourceDevices.isEmpty)

                Button(action: { viewModel.prepareComparison() }) {
                    Label("Compare Scans", systemImage: "rectangle.split.2x2")
                }
                .disabled(viewModel.sourceDevices.isEmpty || viewModel.history.isEmpty)

                Divider()

                Button(action: { viewModel.showRulesManager = true }) {
                    Label("Custom Rules", systemImage: "doc.badge.gearshape")
                }

                if !viewModel.config.rulesURL.isEmpty {
                    Button(action: { viewModel.updateRules() }) {
                        Label("Update Rules", systemImage: "arrow.down.circle")
                    }
                    .disabled(viewModel.isUpdatingRules)
                }
            } label: {
                Label("More", systemImage: "ellipsis.circle")
            }
            .help("More actions")
        }

        ToolbarItem(placement: .status) {
            HStack(spacing: 6) {
                Circle()
                    .fill(statusColor)
                    .frame(width: 7, height: 7)

                Group {
                    if viewModel.isScanning {
                        Text(viewModel.statusMessage)
                    } else if let err = viewModel.errorMessage {
                        Text(err).foregroundStyle(.red)
                    } else if viewModel.sourceDevices.isEmpty {
                        Text("No data")
                    } else {
                        Text("\(viewModel.sourceDevices.count) device\(viewModel.sourceDevices.count == 1 ? "" : "s")")
                    }
                }
                .font(.caption)
                .lineLimit(1)

                if viewModel.rulesVersion > 0 {
                    Text("v\(viewModel.rulesVersion)")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                        .help("Vulnerability rules version")
                }

                if viewModel.isUpdatingRules {
                    ProgressView()
                        .progressViewStyle(.circular)
                        .controlSize(.small)
                        .scaleEffect(0.5)
                }

                if RuleUpdater.isCacheStale() {
                    Image(systemName: "clock.arrow.circlepath")
                        .font(.caption2)
                        .foregroundStyle(.orange)
                        .help("Rules update available")
                }

                if viewModel.userRole != .admin {
                    Text("[\(viewModel.userRole.rawValue)]")
                        .font(.caption2).foregroundStyle(.secondary)
                }
            }
        }
    }

    // MARK: - Export with Preview (Tier 2.16, 4.31)
    private func showExportHTML() {
        let html = viewModel.exportHTML()
        viewModel.showExportPreview(html, format: "HTML") { saveExport(html, type: .html, name: "scan-report.html") }
    }

    private func showExportCSV() {
        let csv = viewModel.exportCSV()
        viewModel.showExportPreview(csv, format: "CSV") { saveExport(csv, type: .commaSeparatedText, name: "scan-report.csv") }
    }

    private func showExportJSON() {
        let json = viewModel.exportJSON()
        viewModel.showExportPreview(json, format: "JSON") { saveExport(json, type: .json, name: "scan-report.json") }
    }

    private func showExportSIEM(_ format: SIEMFormat) {
        let content = viewModel.exportSIEM(format: format)
        viewModel.showExportPreview(content, format: format.rawValue) { saveExport(content, type: .plainText, name: "scan-export.\(format.rawValue.lowercased())") }
    }

    private func saveExport(_ content: String, type: UTType, name: String) {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [type]
        panel.nameFieldStringValue = name
        panel.begin { response in
            if response == .OK, let url = panel.url {
                do {
                    try content.write(to: url, atomically: true, encoding: .utf8)
                    AuditLogger.shared.log(action: .exportPerformed, detail: "Exported \(url.lastPathComponent)", category: .export)
                    viewModel.showToast(message: "Exported to \(url.lastPathComponent)")
                } catch {
                    viewModel.errorMessage = "Failed to export: \(error.localizedDescription)"
                }
            }
        }
    }

    // MARK: - Status
    private var statusColor: Color {
        if viewModel.isScanning { return .orange }
        if viewModel.isUpdatingRules { return .orange }
        if viewModel.sourceDevices.isEmpty { return .gray }
        if viewModel.sourceDevices.contains(where: { $0.vulnerabilities.contains(where: { $0.severity >= 9 }) }) { return .red }
        if viewModel.sourceDevices.contains(where: { $0.vulnerabilities.contains(where: { $0.severity >= 7 }) }) { return .orange }
        return .green
    }

    private func riskBadge(score: Double) -> some View {
        riskBadgeText(score)
            .font(.caption2).bold()
            .foregroundStyle(.white)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(riskColor(score))
            .clipShape(.capsule)
            .accessibilityLabel("Risk score \(String(format: "%.1f", score))")
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

            let sourceDevices = viewModel.sourceDevices

            if sourceDevices.count < 2 {
                EmptyStateView(icon: "point.3.connected.trianglepath.dotted", title: "Not enough devices", message: "Need at least 2 devices to render topology")
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
        .frame(minWidth: 450, idealWidth: 550, minHeight: 450, idealHeight: 550)
        .onExitCommand { showTopology = false }
    }

    // MARK: - Audit Log Sheet (Tier 3.20)
    private var auditLogSheet: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Audit Log").font(.headline)
                Spacer()
                Button("Export JSON") {
                    let json = viewModel.exportAuditLog()
                    saveExport(json, type: .json, name: "audit-log.json")
                }
                .controlSize(.small)
                Button("Close") { viewModel.showAuditLog = false }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
            }
            .padding()

            if viewModel.auditEvents.isEmpty {
                EmptyStateView(icon: "list.bullet.clipboard", title: "No events", message: "Audit events will appear here as actions are performed")
            } else {
                List(viewModel.auditEvents) { event in
                    HStack {
                        Circle().fill(eventColor(event.category)).frame(width: 6, height: 6)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(event.action.rawValue).font(.caption).bold()
                            Text(event.detail).font(.caption2).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Text(event.timestamp.formatted(date: .numeric, time: .shortened))
                            .font(.caption2).foregroundStyle(.tertiary)
                    }
                    .padding(.vertical, 2)
                }
                .listStyle(.plain)
            }
        }
        .frame(minWidth: 450, idealWidth: 500, minHeight: 350, idealHeight: 400)
    }

    private func eventColor(_ category: AuditCategory) -> Color {
        switch category {
        case .scanning: return .blue
        case .configuration: return .orange
        case .security: return .red
        case .dataManagement: return .purple
        case .export: return .green
        case .system: return .gray
        }
    }

    // MARK: - Profile Sheet (Tier 3.21)
    private var profileSheet: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Configuration Profiles").font(.headline)
                Spacer()
                Button("Save Current") {
                    let name = "Profile \(ProfileManager.shared.all().count + 1)"
                    viewModel.saveProfile(name: name)
                    viewModel.showToast(message: "Profile saved")
                }
                .controlSize(.small)
                Button("Close") { viewModel.showProfiles = false }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
            }
            .padding()

            let profiles = ProfileManager.shared.all()
            if profiles.isEmpty {
                EmptyStateView(icon: "square.3.layers.3d", title: "No profiles", message: "Save current configuration as a reusable profile")
            } else {
                List(profiles) { profile in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(profile.name).font(.body)
                            Text("Ports: \(profile.config.portRange.lowerBound)-\(profile.config.portRange.upperBound), Timeout: \(String(format: "%.1f", profile.config.timeout))s")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button("Apply") {
                            viewModel.applyProfile(profile.name)
                            viewModel.showProfiles = false
                        }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.small)
                        Button("Delete", role: .destructive) {
                            ProfileManager.shared.delete(name: profile.name)
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                    }
                    .padding(.vertical, 4)
                }
                .listStyle(.plain)
            }
        }
        .frame(minWidth: 400, idealWidth: 450, minHeight: 300, idealHeight: 360)
    }
}

// MARK: - Supporting Views
struct FilterChip: View {
    let label: String
    let isSelected: Bool
    let color: Color
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 3) {
                if isSelected {
                    Image(systemName: "checkmark.circle.fill").font(.system(size: 8))
                }
                Text(label).font(.caption2).bold()
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(isSelected ? color : Color(nsColor: .controlBackgroundColor))
            .foregroundStyle(isSelected ? .white : .primary)
            .clipShape(.capsule)
            .overlay(Capsule().stroke(isSelected ? color : Color.gray.opacity(0.3), lineWidth: 1))
        }
        .buttonStyle(.plain)
    }
}

struct DeviceDetailRow: View {
    let device: Device
    let tags: [Tag]

    var body: some View {
        HStack(spacing: 8) {
            riskSymbol(device.riskScore)
                .foregroundStyle(riskColor(device.riskScore))
                .frame(width: 16)
            VStack(alignment: .leading, spacing: 2) {
                Text(device.host ?? device.ip).font(.body).lineLimit(1)
                HStack(spacing: 4) {
                    Text(device.ip).font(.caption).foregroundStyle(.secondary)
                    if let os = device.os {
                        Text(os).font(.caption2).foregroundStyle(.tertiary)
                    }
                }
            }
            Spacer()
            HStack(spacing: 4) {
                Text("\(device.ports.filter { $0.state == .open }.count)").font(.caption2).foregroundStyle(.secondary)
                Text("\(device.vulnerabilities.count)").font(.caption2).foregroundStyle(.secondary)
            }
            riskBadgeText(device.riskScore)
                .font(.system(size: 8)).bold()
                .foregroundStyle(.white)
                .padding(.horizontal, 4).padding(.vertical, 2)
                .background(riskColor(device.riskScore))
                .clipShape(RoundedRectangle(cornerRadius: 3))
        }
        .padding(8)
        .background(.surfaceSecondary)
        .clipShape(RoundedRectangle(cornerRadius: 6))
    }
}

struct VulnRowMini: View {
    let vuln: Vuln

    var body: some View {
        HStack(spacing: 6) {
            riskBadgeText(vuln.severity)
                .font(.system(size: 7)).bold()
                .foregroundStyle(.white)
                .padding(.horizontal, 3).padding(.vertical, 1)
                .background(riskColor(vuln.severity))
                .clipShape(RoundedRectangle(cornerRadius: 2))
            Text(vuln.id).font(.caption).foregroundStyle(.secondary)
            Text(vuln.description).font(.caption).lineLimit(1)
            Spacer()
            if let cve = vuln.cve {
                Text(cve).font(.caption2).foregroundStyle(.blue)
            }
        }
        .padding(.vertical, 4)
    }
}

// MARK: - Keyboard Shortcuts (Tier 2.15)

