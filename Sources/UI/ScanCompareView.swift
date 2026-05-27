import SwiftUI
import Charts
import Core

struct ScanCompareView: View {
    let currentDevices: [Device]
    let history: [ScanSummary]
    let loadDevices: (String) -> [Device]?

    @State private var selectedBaselineID: String?
    @State private var baselineDevices: [Device] = []
    @Environment(\.dismiss) private var dismiss

    private var baselineRisk: Double { baselineDevices.map(\.riskScore).max() ?? 0 }
    private var comparisonRisk: Double { currentDevices.map(\.riskScore).max() ?? 0 }
    private var baselineVulns: Int { baselineDevices.reduce(0) { $0 + $1.vulnerabilities.count } }
    private var comparisonVulns: Int { currentDevices.reduce(0) { $0 + $1.vulnerabilities.count } }
    private var baselineCount: Int { baselineDevices.count }
    private var comparisonCount: Int { currentDevices.count }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Scan Comparison").font(.headline)
                Spacer()
                Button("Close") { dismiss() }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
            }
            .padding()

            if history.isEmpty {
                VStack(spacing: 12) {
                    Spacer()
                    Image(systemName: "clock.arrow.circlepath").font(.system(size: 32)).foregroundStyle(.tertiary)
                    Text("No previous scans to compare against")
                        .foregroundStyle(.secondary)
                    Spacer()
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(spacing: 4) {
                    Picker("Compare against", selection: $selectedBaselineID) {
                        Text("Select a previous scan...").tag(nil as String?)
                        ForEach(history) { summary in
                            Text(summary.timestamp.formatted(date: .abbreviated, time: .shortened))
                                .tag(summary.scanID as String?)
                        }
                    }
                    .pickerStyle(.menu)
                    .labelsHidden()
                    .onChange(of: selectedBaselineID) { _, newID in
                        guard let id = newID else { baselineDevices = []; return }
                        baselineDevices = loadDevices(id) ?? []
                    }

                    if !baselineDevices.isEmpty {
                        Text("Comparing current scan against \(history.first(where: { $0.scanID == selectedBaselineID })?.timestamp.formatted(date: .abbreviated, time: .shortened) ?? "")")
                            .font(.caption).foregroundStyle(.tertiary)
                    }
                }
                .padding(.horizontal)

                if baselineDevices.isEmpty && selectedBaselineID != nil {
                    VStack(spacing: 8) {
                        Spacer()
                        ProgressView()
                        Text("Loading baseline scan...")
                            .font(.caption).foregroundStyle(.secondary)
                        Spacer()
                    }
                } else if !baselineDevices.isEmpty {
                    ScrollView {
                        VStack(spacing: 20) {
                            diffCards
                            riskChart
                            deviceDiffTable
                        }
                        .padding()
                    }
                } else {
                    Spacer()
                }
            }
        }
        .frame(minWidth: 500, idealWidth: 600, minHeight: 400, idealHeight: 500)
        .onAppear {
            if let first = history.first {
                selectedBaselineID = first.scanID
                baselineDevices = loadDevices(first.scanID) ?? []
            }
        }
    }

    private var diffCards: some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 140))], spacing: 12) {
            DiffCard(title: "Devices", before: "\(baselineCount)", after: "\(comparisonCount)", delta: Double(comparisonCount - baselineCount))
            DiffCard(title: "Vulnerabilities", before: "\(baselineVulns)", after: "\(comparisonVulns)", delta: Double(comparisonVulns - baselineVulns))
            DiffCard(title: "Max Risk", before: String(format: "%.1f", baselineRisk), after: String(format: "%.1f", comparisonRisk), delta: comparisonRisk - baselineRisk)
        }
    }

    private var riskChart: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Device Risk Distribution").font(.headline)
            Chart {
                ForEach(baselineDevices) { d in
                    PointMark(x: .value("Device", d.ip), y: .value("Baseline", d.riskScore))
                        .foregroundStyle(.blue.opacity(0.5))
                }
                ForEach(currentDevices) { d in
                    PointMark(x: .value("Device", d.ip), y: .value("Current", d.riskScore))
                        .foregroundStyle(.orange.opacity(0.7))
                }
            }
            .chartLegend(position: .bottom)
            .frame(height: 200)
        }
        .padding()
        .background(.surfacePrimary)
        .clipShape(RoundedRectangle(cornerRadius: 10))
    }

    private var deviceDiffTable: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Device Changes").font(.headline)
            let baselineIPs = Set(baselineDevices.map(\.ip))
            let comparisonIPs = Set(currentDevices.map(\.ip))
            let added = comparisonIPs.subtracting(baselineIPs)
            let removed = baselineIPs.subtracting(comparisonIPs)
            let changed = comparisonIPs.intersection(baselineIPs).filter { ip in
                guard let b = baselineDevices.first(where: { $0.ip == ip }),
                      let c = currentDevices.first(where: { $0.ip == ip }) else { return false }
                return b.riskScore != c.riskScore || b.vulnerabilities.count != c.vulnerabilities.count
            }
            if added.isEmpty && removed.isEmpty && changed.isEmpty {
                Text("No changes detected").foregroundStyle(.secondary)
            } else {
                if !added.isEmpty {
                    Label("\(added.count) device(s) added", systemImage: "plus.circle").foregroundStyle(.green)
                }
                if !removed.isEmpty {
                    Label("\(removed.count) device(s) removed", systemImage: "minus.circle").foregroundStyle(.red)
                }
                if !changed.isEmpty {
                    Label("\(changed.count) device(s) changed", systemImage: "arrow.up.arrow.down").foregroundStyle(.orange)
                }
            }
        }
        .padding()
        .background(.surfacePrimary)
        .clipShape(RoundedRectangle(cornerRadius: 10))
    }
}

private struct DiffCard: View {
    let title: String
    let before: String
    let after: String
    let delta: Double

    var body: some View {
        VStack(spacing: 4) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            HStack(spacing: 8) {
                VStack(spacing: 2) {
                    Text("Before").font(.system(size: 8)).foregroundStyle(.secondary)
                    Text(before).font(.headline)
                }
                Image(systemName: delta > 0 ? "arrow.right" : delta < 0 ? "arrow.left" : "minus")
                    .font(.caption).foregroundStyle(.tertiary)
                VStack(spacing: 2) {
                    Text("After").font(.system(size: 8)).foregroundStyle(.secondary)
                    Text(after).font(.headline)
                }
            }
            if delta != 0 {
                Text("\(delta > 0 ? "+" : "")\(String(format: "%.0f", delta))")
                    .font(.caption2).bold()
                    .foregroundStyle(delta > 0 ? .red : .green)
            }
        }
        .padding()
        .frame(maxWidth: .infinity)
        .background(.surfacePrimary)
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(.borderStandard, lineWidth: 1))
    }
}
