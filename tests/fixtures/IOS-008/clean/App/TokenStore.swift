import Security

// Not kSecAttrAccessibleAlways: it is deprecated and readable before first unlock (§4.4).
func save(_ token: Data) {
    let item: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: "session",
        kSecValueData as String: token,
        kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    ]
    SecItemAdd(item as CFDictionary, nil)
    print("migrated away from kSecAttrAccessibleAlways")
}
