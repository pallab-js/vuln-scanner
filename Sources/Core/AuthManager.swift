import Foundation
import LocalAuthentication

public enum AuthError: Error, LocalizedError, Sendable {
    case notAvailable
    case cancelled
    case denied
    case unknown(String)

    public var errorDescription: String? {
        switch self {
        case .notAvailable: return "Biometric authentication not available on this device"
        case .cancelled: return "Authentication cancelled"
        case .denied: return "Authentication denied"
        case .unknown(let msg): return "Authentication error: \(msg)"
        }
    }
}

public enum AuthResult: Sendable {
    case authenticated(role: UserRole)
    case unauthenticated
}

public final class AuthManager: @unchecked Sendable {
    public static let shared = AuthManager()
    public private(set) var currentUser: String = "local"
    public private(set) var currentRole: UserRole = .admin
    public private(set) var isAuthenticated = false

    private let context = LAContext()

    private init() {}

    public func authenticate(reason: String = "Unlock LAN Scanner") async -> AuthResult {
        let context = LAContext()
        var error: NSError?

        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            isAuthenticated = true
            currentRole = .admin
            return .authenticated(role: .admin)
        }

        do {
            let success = try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
            if success {
                isAuthenticated = true
                currentRole = .admin
                AuditLogger.shared.log(action: .login, detail: "Biometric authentication successful", category: .security)
                return .authenticated(role: .admin)
            } else {
                isAuthenticated = false
                return .unauthenticated
            }
        } catch LAError.userCancel {
            isAuthenticated = false
            return .unauthenticated
        } catch {
            isAuthenticated = false
            AuditLogger.shared.log(action: .login, detail: "Authentication failed: \(error.localizedDescription)", category: .security)
            return .unauthenticated
        }
    }

    public func logout() {
        isAuthenticated = false
        AuditLogger.shared.log(action: .logout, detail: "User logged out", category: .security)
    }

    public func setRole(_ role: UserRole) {
        currentRole = role
    }

    public func requireRole(_ minimum: UserRole) -> Bool {
        let hierarchy: [UserRole] = [.viewer, .auditor, .operator_, .admin]
        guard let currentIdx = hierarchy.firstIndex(of: currentRole),
              let requiredIdx = hierarchy.firstIndex(of: minimum) else { return false }
        return currentIdx >= requiredIdx
    }
}
