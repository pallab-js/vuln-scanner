import SwiftUI

extension Color {
    static let brandPrimary = Color("brandPrimary", bundle: .main)
    static let brandSecondary = Color("brandSecondary", bundle: .main)
    static let surfacePrimary = Color(nsColor: .windowBackgroundColor)
    static let surfaceSecondary = Color(nsColor: .controlBackgroundColor)
    static let surfaceTertiary = Color(nsColor: .underPageBackgroundColor)
    static let textPrimary = Color(nsColor: .labelColor)
    static let textSecondary = Color(nsColor: .secondaryLabelColor)
    static let textTertiary = Color(nsColor: .tertiaryLabelColor)
    static let borderStandard = Color(nsColor: .separatorColor).opacity(0.6)
    static let borderEmphasis = Color(nsColor: .separatorColor)
}

public extension ShapeStyle where Self == Color {
    static var brandPrimary: Color { .brandPrimary }
    static var brandSecondary: Color { .brandSecondary }
    static var surfacePrimary: Color { .surfacePrimary }
    static var surfaceSecondary: Color { .surfaceSecondary }
    static var surfaceTertiary: Color { .surfaceTertiary }
    static var textPrimary: Color { .textPrimary }
    static var textSecondary: Color { .textSecondary }
    static var textTertiary: Color { .textTertiary }
    static var borderStandard: Color { .borderStandard }
    static var borderEmphasis: Color { .borderEmphasis }
}
