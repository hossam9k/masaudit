// A keychain item (not a Secure Enclave key) gated by .biometryAny alone, OR-ed with the passcode.
import Security

enum TokenVault {
    static func save(_ token: Data) -> OSStatus {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            [.biometryAny, .or, .devicePasscode],
            &error
        ) else { return errSecParam }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "session",
            kSecAttrAccessControl as String: access,
            kSecValueData as String: token,
        ]
        return SecItemAdd(query as CFDictionary, nil)
    }
}
