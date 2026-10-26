// Near miss: the token goes to a shared Keychain access group; only widget preferences go to the group container.
import Foundation
import Security

enum SharedStore {
    static func share(token: Data) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "session",
            kSecAttrAccessGroup as String: "TEAMID.com.example.shared",
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData as String: token,
        ]
        SecItemAdd(query as CFDictionary, nil)
    }

    static func savePreferences(_ preferences: Data) throws {
        guard let group = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: "group.com.example.shared") else { return }
        try preferences.write(to: group.appendingPathComponent("widget-preferences.json"), options: .atomic)
    }
}
