import Security

let sessionAttributes: [String: Any] = [
    kSecValueData as String: Data(),
    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked,
]
let refreshAttributes: [String: Any] = [
    kSecValueData as String: Data(),
    kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
]
