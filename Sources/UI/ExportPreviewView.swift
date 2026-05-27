import SwiftUI
import Core

struct ExportPreviewView: View {
    let content: String
    let format: String
    let onSave: () -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Export Preview — \(format)").font(.headline)
                Spacer()
                Button("Save…") { onSave(); dismiss() }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
                Button("Cancel") { dismiss() }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
            }
            .padding()

            Divider()

            ScrollView {
                Text(content)
                    .font(.body.monospaced())
                    .textSelection(.enabled)
                    .padding()
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .frame(minWidth: 500, idealWidth: 600, minHeight: 400, idealHeight: 500)
    }
}
