import SwiftUI
import Core

func tagColor(_ hex: String) -> Color {
    guard hex.hasPrefix("#"), let val = Int(hex.dropFirst(), radix: 16) else { return .gray }
    let r = Double((val >> 16) & 0xFF) / 255
    let g = Double((val >> 8) & 0xFF) / 255
    let b = Double(val & 0xFF) / 255
    return Color(.sRGB, red: r, green: g, blue: b, opacity: 1)
}

func riskColor(_ score: Double) -> Color {
    switch score { case 9...: .red case 7...: .orange case 4...: .yellow case 1...: .blue default: .gray }
}

func riskLabel(_ score: Double) -> String {
    switch score { case 9...: "CRITICAL" case 7...: "HIGH" case 4...: "MEDIUM" case 1...: "LOW" default: "INFO" }
}

func frameworkColor(_ fw: ComplianceFramework) -> Color {
    switch fw {
    case .pciDSS: return .red
    case .hipaa: return .blue
    case .gdpr: return .purple
    case .soc2: return .green
    case .nist: return .orange
    }
}

func severityColor(_ score: Double) -> Color {
    switch score {
    case 9...: return .red
    case 7...: return .orange
    case 4...: return .yellow
    case 1...: return .blue
    default: return .gray
    }
}
