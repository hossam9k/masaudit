import LocalAuthentication

final class AppLock {
    func unlock(reason: String) async throws -> Bool {
        let context = LAContext()
        return try await context.evaluatePolicy(
            .deviceOwnerAuthentication,
            localizedReason: NSLocalizedString("unlock", comment: "Unlock (biometric)"),
        )
    }
}
