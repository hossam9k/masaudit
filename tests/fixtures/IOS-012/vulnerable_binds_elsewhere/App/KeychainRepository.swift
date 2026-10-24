import Foundation
import Security

final class KeychainRepository {
    func setUserBiometricAuthKey(_ key: Data, account: String) throws {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .biometryCurrentSet, &error
        ) else { throw error!.takeRetainedValue() as Error }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrAccessControl as String: access,
            kSecValueData as String: key,
        ]
        SecItemAdd(query as CFDictionary, nil)
    }
}
