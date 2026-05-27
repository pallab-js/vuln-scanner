import SwiftUI
import Core

struct DeviceRow: View {
    let device: Device
    let tags: [Tag]

    var body: some View {
        HStack(spacing: 8) {
            HStack(spacing: 4) {
                Circle().fill(riskColor(device.riskScore)).frame(width: 8, height: 8)
                Text(riskLabel(device.riskScore))
                    .font(.system(size: 7)).bold()
                    .foregroundStyle(riskColor(device.riskScore))
                    .frame(width: 40, alignment: .leading)
            }
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
}

struct VulnRow: View {
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

struct StatCard: View {
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
