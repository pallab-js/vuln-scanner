import SwiftUI
import Core
import Engine
import API

struct ConfigSheet: View {
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
    @State private var apiKey: String
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
        _apiKey = State(initialValue: config.wrappedValue.apiKey)
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
        .frame(minWidth: 400, idealWidth: 460, minHeight: 400, idealHeight: 560)
        .onExitCommand { dismiss() }
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
                Text("UDP scanning slows scans significantly. Experimental.")
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

                    HStack {
                        Text("API Key:").frame(width: 50, alignment: .trailing)
                        SecureField("Leave empty for no auth", text: $apiKey)
                            .frame(width: 200)
                            .font(.caption)
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
        guard scheduleEnabled, let next = ScanScheduler.shared.nextScanAt else { return "\u{2014}" }
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
        apiEnabled = d.apiEnabled; apiPort = String(d.apiPort); apiKey = d.apiKey
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
        viewModel.updateAPI(enabled: apiEnabled, port: Int(apiPort) ?? 8080, apiKey: apiKey)
        config.autoUpdateRules = autoUpdateRules
        config.rulesURL = rulesURL
        dismiss()
    }
}
