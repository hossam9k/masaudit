import Foundation
import LocalAuthentication
import Security

enum TokenStore {
    static func save(_ token: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "refresh",
            kSecValueData as String: Data(token.utf8),
            kSecAttrAccessible as String: kSecAttrAccessibleAlways,
        ]
        SecItemAdd(query as CFDictionary, nil)
        UserDefaults.standard.set(token, forKey: "authToken")
    }

    static func unlock(completion: @escaping (Bool) -> Void) {
        LAContext().evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                                   localizedReason: "Confirm transfer") { success, _ in
            completion(success)
        }
    }
}
