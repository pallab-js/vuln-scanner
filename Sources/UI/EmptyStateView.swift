import SwiftUI

struct EmptyStateView: View {
    let icon: String
    let title: String
    let message: String
    var actions: [EmptyStateAction] = []

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: icon)
                .font(.system(size: 48))
                .foregroundStyle(.tertiary)

            Text(title)
                .font(.title3).bold()

            Text(message)
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            if !actions.isEmpty {
                HStack(spacing: 12) {
                    ForEach(actions) { action in
                        if action.primary {
                            Button(action: action.action) {
                                Label(action.label, systemImage: action.icon)
                            }
                            .buttonStyle(BorderedProminentButtonStyle())
                        } else {
                            Button(action: action.action) {
                                Label(action.label, systemImage: action.icon)
                            }
                            .buttonStyle(BorderedButtonStyle())
                        }
                    }
                }
                .padding(.top, 4)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(40)
    }
}

struct EmptyStateAction: Identifiable {
    let id = UUID()
    let label: String
    let icon: String
    let primary: Bool
    let action: () -> Void

    init(label: String, icon: String, primary: Bool = false, action: @escaping () -> Void) {
        self.label = label
        self.icon = icon
        self.primary = primary
        self.action = action
    }
}
