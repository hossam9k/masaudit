import Security

// kSecAttrAccessibleWhenUnlocked alone would migrate with backups; keep ThisDeviceOnly.
let sessionAttributes: [String: Any] = [
    kSecValueData as String: Data(),
    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
]
let refreshAttributes: [String: Any] = [
    kSecValueData as String: Data(),
    kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
]
