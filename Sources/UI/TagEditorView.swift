import SwiftUI
import Core

struct TagEditorView: View {
    @Bindable var viewModel: ScannerViewModel
    let deviceIP: String
    @Environment(\.dismiss) private var dismiss
    @State private var newTagName = ""
    @State private var selectedColor = "#2196F3"

    private let presetColors = [
        "#F44336", "#E91E63", "#9C27B0", "#673AB7",
        "#3F51B5", "#2196F3", "#009688", "#4CAF50",
        "#FF9800", "#FF5722", "#795548", "#607D8B"
    ]

    var body: some View {
        VStack(spacing: 16) {
            HStack {
                Text("Manage Tags — \(deviceIP)").font(.headline)
                Spacer()
                Button("Done") { dismiss() }.buttonStyle(.borderedProminent).controlSize(.small)
            }

            HStack(spacing: 8) {
                TextField("New tag name…", text: $newTagName)
                    .textFieldStyle(.roundedBorder)
                Button("Add") {
                    let trimmed = newTagName.trimmingCharacters(in: .whitespaces)
                    guard !trimmed.isEmpty else { return }
                    viewModel.addTag(trimmed, color: selectedColor, to: deviceIP)
                    newTagName = ""
                }
                .buttonStyle(.borderedProminent)
                .disabled(newTagName.trimmingCharacters(in: .whitespaces).isEmpty)
            }

            LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 6), count: 6), spacing: 6) {
                ForEach(presetColors, id: \.self) { hex in
                    Circle()
                        .fill(tagColor(hex))
                        .frame(width: 24, height: 24)
                        .overlay(
                            Circle().stroke(selectedColor == hex ? Color.primary : Color.clear, lineWidth: 2)
                        )
                        .onTapGesture { selectedColor = hex }
                }
            }

            let currentTags = viewModel.deviceTags[deviceIP, default: []]
            if currentTags.isEmpty {
                Text("No tags for this device").foregroundStyle(.secondary).font(.caption)
            } else {
                ScrollView {
                    VStack(spacing: 6) {
                        ForEach(currentTags) { tag in
                            HStack {
                                Circle().fill(tagColor(tag.color)).frame(width: 10, height: 10)
                                Text(tag.name).font(.body)
                                Spacer()
                                Button(role: .destructive) {
                                    viewModel.removeTag(tag, from: deviceIP)
                                } label: {
                                    Image(systemName: "trash").font(.caption)
                                }
                                .buttonStyle(.plain)
                            }
                            .padding(.horizontal, 8).padding(.vertical, 4)
                            .background(Color(nsColor: .controlBackgroundColor))
                            .clipShape(.rect(cornerRadius: 6))
                        }
                    }
                }
            }
        }
        .padding()
        .frame(width: 340, height: 340)
    }

}
