import LocalAuthentication

func biometricsAvailable() -> Bool {
    LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
}
