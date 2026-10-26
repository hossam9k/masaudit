// Near miss: .biometryCurrentSet (invalidated on re-enrollment); biometryAny only in a comment and a string.
import LocalAuthentication
import Security

enum TokenVault {
    // Don't use .biometryAny here: a newly enrolled finger would unlock the token.
    static let auditNote = "kSecAccessControlBiometryAny rejected in review"

    static func access() -> SecAccessControl? {
        SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            [.biometryCurrentSet, .or, .devicePasscode],
            nil
        )
    }

    static func biometryKind() -> LABiometryType { LAContext().biometryType }
}
