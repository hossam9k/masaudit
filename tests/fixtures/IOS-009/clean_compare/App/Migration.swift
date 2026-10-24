import Foundation
import KeychainAccess

func needsMigration(_ dict: [String: Any]) -> Bool {
    // Reading the class during a migration is not a write.
    if let a = dict[kSecAttrAccessible as String] as? String, a == (kSecAttrAccessibleWhenUnlocked as String) {
        return true
    }
    switch dict[kSecAttrAccessible as String] as? String {
    case kSecAttrAccessibleAfterFirstUnlock as String?: return true
    default: return false
    }
}

final class TokenStore {
    private let keychain = Keychain(service: "com.example.auth").accessibility(.whenUnlockedThisDeviceOnly)
    func save(_ token: String) { keychain["token"] = token }
}

final class LegacyReader {
    // Reads another app's items; never writes.
    private let keychain = Keychain(service: "com.example.legacy", accessGroup: "TEAMID.legacy")
    func legacyKey() throws -> Data? { try keychain.getData("key") }
}
