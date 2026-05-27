import SwiftUI

struct SkeletonRow: View {
    var body: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(.quaternary)
                .frame(width: 8, height: 8)
            VStack(alignment: .leading, spacing: 4) {
                RoundedRectangle(cornerRadius: 4)
                    .fill(.quaternary)
                    .frame(width: 120, height: 12)
                RoundedRectangle(cornerRadius: 4)
                    .fill(.quinary)
                    .frame(width: 80, height: 8)
            }
            Spacer()
            RoundedRectangle(cornerRadius: 4)
                .fill(.quaternary)
                .frame(width: 40, height: 16)
        }
        .padding(.vertical, 6)
        .shimmering()
    }
}

struct SkeletonCard: View {
    var body: some View {
        HStack(spacing: 12) {
            RoundedRectangle(cornerRadius: 6)
                .fill(.quaternary)
                .frame(width: 24, height: 24)
            VStack(alignment: .leading, spacing: 4) {
                RoundedRectangle(cornerRadius: 4)
                    .fill(.quaternary)
                    .frame(width: 60, height: 20)
                RoundedRectangle(cornerRadius: 4)
                    .fill(.quinary)
                    .frame(width: 40, height: 10)
            }
        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.surfacePrimary)
        .clipShape(RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(.borderStandard, lineWidth: 1))
        .shimmering()
    }
}

private struct ShimmerModifier: ViewModifier {
    @State private var isAnimating = false

    func body(content: Content) -> some View {
        content
            .overlay(
                LinearGradient(
                    colors: [.clear, .white.opacity(0.3), .clear],
                    startPoint: .leading,
                    endPoint: .trailing
                )
                .offset(x: isAnimating ? 400 : -400)
                .mask(content)
                .animation(.linear(duration: 1.5).repeatForever(autoreverses: false), value: isAnimating)
            )
            .onAppear { isAnimating = true }
            .onDisappear { isAnimating = false }
    }
}

private extension View {
    func shimmering() -> some View {
        modifier(ShimmerModifier())
    }
}
