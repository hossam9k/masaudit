import LocalAuthentication

final class UnlockViewModel {
    var isUnlocked = false

    func unlock() {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else { return }
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                               localizedReason: "Unlock your account") { success, _ in
            self.isUnlocked = success
        }
    }
}
