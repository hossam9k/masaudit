import Security

func save(_ token: Data) {
    let item: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: "session",
        kSecValueData as String: token,
        kSecAttrAccessible as String: kSecAttrAccessibleAlways,   // background refresh "fix"
    ]
    SecItemAdd(item as CFDictionary, nil)
}
