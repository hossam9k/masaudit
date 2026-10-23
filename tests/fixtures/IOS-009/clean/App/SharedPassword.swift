import Security

// A website password the user wants on all their devices: synced on purpose.
let sharedAttributes: [String: Any] = [
    kSecValueData as String: Data(),
    kSecAttrSynchronizable as String: true,
    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked,
]
