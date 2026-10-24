import LocalAuthentication

final class BiometricsService {
    func confirm() async throws -> Bool {
        try await LAContext().evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "x")
    }
}
