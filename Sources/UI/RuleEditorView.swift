import SwiftUI
import Core

struct RuleEditorView: View {
    @Bindable var viewModel: ScannerViewModel
    @Environment(\.dismiss) private var dismiss
    let rule: CustomRule?

    @State private var id: String
    @State private var category: RuleCategory
    @State private var severity: Double
    @State private var description: String
    @State private var recommendation: String
    @State private var service: String
    @State private var port: String
    @State private var pattern: String
    @State private var matchOS: Bool
    @State private var compliancePCI: Bool
    @State private var complianceHIPAA: Bool
    @State private var complianceGDPR: Bool
    @State private var complianceSOC2: Bool
    @State private var complianceNIST: Bool
    @State private var testBanner: String
    @State private var testResult: String?
    @State private var testError: String?
    @State private var showTestError = false

    private var isEditing: Bool { rule != nil }

    init(viewModel: ScannerViewModel, rule: CustomRule?) {
        self.viewModel = viewModel
        self.rule = rule
        _id = State(initialValue: rule?.id ?? UUID().uuidString)
        _category = State(initialValue: rule?.category ?? .outdatedVersion)
        _severity = State(initialValue: rule?.severity ?? 5.0)
        _description = State(initialValue: rule?.description ?? "")
        _recommendation = State(initialValue: rule?.recommendation ?? "")
        _service = State(initialValue: rule?.service ?? "")
        _port = State(initialValue: rule?.port.map(String.init) ?? "")
        _pattern = State(initialValue: rule?.pattern ?? "")
        _matchOS = State(initialValue: rule?.matchOS ?? false)
        let compliance = rule?.compliance ?? []
        _compliancePCI = State(initialValue: compliance.contains("PCI-DSS"))
        _complianceHIPAA = State(initialValue: compliance.contains("HIPAA"))
        _complianceGDPR = State(initialValue: compliance.contains("GDPR"))
        _complianceSOC2 = State(initialValue: compliance.contains("SOC2"))
        _complianceNIST = State(initialValue: compliance.contains("NIST"))
        _testBanner = State(initialValue: "")
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text(isEditing ? "Edit Rule" : "New Rule").font(.headline)
                Spacer()
                Button("Cancel") { dismiss() }
                    .buttonStyle(.plain)
            }
            .padding()

            Form {
                Section("Identity") {
                    TextField("ID", text: $id)
                        .font(.caption)
                    Picker("Category", selection: $category) {
                        ForEach(RuleCategory.allCases, id: \.self) { cat in
                            Label(cat.rawValue, systemImage: cat.systemImage).tag(cat)
                        }
                    }
                }

                Section("Severity & Description") {
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text("Severity: \(String(format: "%.1f", severity))")
                            Spacer()
                            Text(severityLabel).font(.caption).foregroundStyle(severityColor)
                        }
                        Slider(value: $severity, in: 0...10, step: 0.5)
                    }
                    TextField("Description", text: $description, axis: .vertical)
                        .lineLimit(2...4)
                    TextField("Recommendation", text: $recommendation, axis: .vertical)
                        .lineLimit(2...3)
                }

                Section("Match Conditions") {
                    if category == .dangerousPort {
                        TextField("Port number", text: $port)
                            .font(.body)
                    } else {
                        TextField("Service name (e.g. ssh, http)", text: $service)
                            .font(.body)
                    }

                    if category == .outdatedVersion || category == .weakCipher || category == .eolSystem {
                        TextField("Regex pattern", text: $pattern)
                            .font(.body.monospaced())
                        if category == .eolSystem {
                            Toggle("Match against OS fingerprint", isOn: $matchOS)
                        }
                    }
                }

                Section("Compliance Frameworks") {
                    HStack(spacing: 12) {
                        toggleBadge("PCI-DSS", color: .red, isOn: $compliancePCI)
                        toggleBadge("HIPAA", color: .blue, isOn: $complianceHIPAA)
                        toggleBadge("GDPR", color: .purple, isOn: $complianceGDPR)
                    }
                    HStack(spacing: 12) {
                        toggleBadge("SOC2", color: .green, isOn: $complianceSOC2)
                        toggleBadge("NIST", color: .orange, isOn: $complianceNIST)
                    }
                }

                if !pattern.isEmpty && (category == .outdatedVersion || category == .weakCipher || category == .eolSystem) {
                    Section("Regex Tester") {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Paste a banner or OS string to test the pattern:").font(.caption)
                            TextEditor(text: $testBanner)
                                .font(.body.monospaced())
                                .frame(height: 60)
                                .overlay(RoundedRectangle(cornerRadius: 4).stroke(Color(nsColor: .separatorColor), lineWidth: 1))

                            Button("Test Pattern") { runTest() }
                                .buttonStyle(.bordered)
                                .disabled(pattern.isEmpty || testBanner.isEmpty)

                            if let result = testResult {
                                HStack {
                                    Image(systemName: result == "Match!" ? "checkmark.circle.fill" : "xmark.circle.fill")
                                        .foregroundStyle(result == "Match!" ? .green : .red)
                                    Text(result)
                                        .font(.caption).foregroundStyle(result == "Match!" ? .green : .red)
                                }
                            }
                            if let error = testError {
                                Text(error).font(.caption).foregroundStyle(.red)
                            }
                        }
                    }
                }
            }
            .formStyle(.grouped)

            HStack(spacing: 16) {
                Button("Delete", role: .destructive) {
                    CustomRulesStore.shared.delete(id: id)
                    viewModel.customRules = CustomRulesStore.shared.load()
                    dismiss()
                }
                .disabled(!isEditing)
                .buttonStyle(.bordered)

                Spacer()

                Button("Cancel") { dismiss() }
                    .buttonStyle(.bordered)

                Button(isEditing ? "Save" : "Add Rule") { save() }
                    .buttonStyle(.borderedProminent)
                    .disabled(description.isEmpty)
            }
            .padding()
        }
        .frame(minWidth: 420, idealWidth: 480, minHeight: 420, idealHeight: 580)
        .onExitCommand { dismiss() }
    }

    private func toggleBadge(_ name: String, color: Color, isOn: Binding<Bool>) -> some View {
        Button {
            isOn.wrappedValue.toggle()
        } label: {
            Text(name).font(.caption2).bold()
                .padding(.horizontal, 8).padding(.vertical, 4)
                .background(isOn.wrappedValue ? color : Color(nsColor: .controlBackgroundColor))
                .foregroundStyle(isOn.wrappedValue ? .white : .primary)
                .clipShape(.capsule)
                .overlay(Capsule().stroke(isOn.wrappedValue ? color : Color.gray.opacity(0.3), lineWidth: 1))
        }
        .buttonStyle(.plain)
    }

    private var severityLabel: String {
        switch severity {
        case 9...: return "CRITICAL"
        case 7...: return "HIGH"
        case 4...: return "MEDIUM"
        case 1...: return "LOW"
        default: return "INFO"
        }
    }

    private var severityColor: Color {
        switch severity {
        case 9...: return .red
        case 7...: return .orange
        case 4...: return .yellow
        case 1...: return .blue
        default: return .gray
        }
    }

    private func runTest() {
        testResult = nil
        testError = nil
        guard !pattern.isEmpty, !testBanner.isEmpty else { return }
        do {
            let regex = try Regex(pattern)
            if testBanner.contains(regex) {
                testResult = "Match!"
            } else {
                testResult = "No match"
            }
        } catch {
            testError = "Invalid regex: \(error.localizedDescription)"
        }
    }

    private func save() {
        var compliance: [String] = []
        if compliancePCI { compliance.append("PCI-DSS") }
        if complianceHIPAA { compliance.append("HIPAA") }
        if complianceGDPR { compliance.append("GDPR") }
        if complianceSOC2 { compliance.append("SOC2") }
        if complianceNIST { compliance.append("NIST") }

        let rule = CustomRule(
            id: id, category: category, severity: severity,
            description: description, recommendation: recommendation,
            service: service.isEmpty ? nil : service,
            port: Int(port), pattern: pattern.isEmpty ? nil : pattern,
            matchOS: matchOS, compliance: compliance
        )
        CustomRulesStore.shared.upsert(rule)
        viewModel.customRules = CustomRulesStore.shared.load()
        dismiss()
    }
}

// MARK: - Rules Manager
struct RulesManagerView: View {
    @Bindable var viewModel: ScannerViewModel
    @Environment(\.dismiss) private var dismiss
    @State private var showNewRule = false

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Custom Rules (\(viewModel.customRules.count))")
                    .font(.headline)
                Spacer()
                Button("New Rule") { showNewRule = true }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
                Button("Done") { dismiss() }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
            }
            .padding()

            if viewModel.customRules.isEmpty {
                VStack(spacing: 12) {
                    Image(systemName: "doc.badge.plus").font(.system(size: 36)).foregroundStyle(.tertiary)
                    Text("No custom rules yet").foregroundStyle(.secondary)
                    Text("Create rules to detect application-specific vulnerabilities").font(.caption).foregroundStyle(.tertiary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List {
                    ForEach(viewModel.customRules) { rule in
                        Button {
                            viewModel.editingRule = rule
                            viewModel.showRuleEditor = true
                        } label: {
                            HStack(spacing: 8) {
                                severityDot(rule.severity).frame(width: 8)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(rule.description).font(.body).lineLimit(1)
                                    HStack(spacing: 4) {
                                        Text(rule.category.rawValue).font(.caption2).foregroundStyle(.secondary)
                                        Text(String(format: "%.1f", rule.severity)).font(.caption2).foregroundStyle(.secondary)
                                        if let s = rule.service {
                                            Text(s).font(.caption2).foregroundStyle(.blue)
                                        }
                                        if let p = rule.port {
                                            Text(":\(p)").font(.caption2).foregroundStyle(.blue)
                                        }
                                    }
                                }
                                Spacer()
                                Image(systemName: "chevron.right").font(.caption2).foregroundStyle(.tertiary)
                            }
                            .padding(.vertical, 4)
                        }
                        .buttonStyle(.plain)
                        .contextMenu {
                            Button("Edit") {
                                viewModel.editingRule = rule
                                viewModel.showRuleEditor = true
                            }
                            Divider()
                            Button("Delete", role: .destructive) {
                                CustomRulesStore.shared.delete(id: rule.id)
                                viewModel.customRules = CustomRulesStore.shared.load()
                            }
                        }
                    }
                }
                .listStyle(.plain)
            }
        }
        .frame(minWidth: 380, idealWidth: 440, minHeight: 360, idealHeight: 420)
        .onExitCommand { dismiss() }
        .sheet(isPresented: $showNewRule) {
            RuleEditorView(viewModel: viewModel, rule: nil)
        }
        .sheet(isPresented: $viewModel.showRuleEditor) {
            RuleEditorView(viewModel: viewModel, rule: viewModel.editingRule)
        }
    }

    private func severityDot(_ score: Double) -> some View {
        let color: Color = switch score {
        case 9...: .red case 7...: .orange case 4...: .yellow case 1...: .blue default: .gray
        }
        return Circle().fill(color).frame(width: 8, height: 8)
    }
}
