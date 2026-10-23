import Foundation
import LocalAuthentication
import Security

func signWithBiometricKey(tag: Data, message: Data, reason: String) throws -> Data {
    let context = LAContext()
    context.localizedReason = reason
    // Optional pre-check of the policy is fine: context.evaluatePolicy is never the gate here.
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: tag,
        kSecReturnRef as String: true,
        kSecUseAuthenticationContext as String: context
    ]
    var item: CFTypeRef?
    _ = SecItemCopyMatching(query as CFDictionary, &item)
    var error: Unmanaged<CFError>?
    let signature = SecKeyCreateSignature(item as! SecKey, .ecdsaSignatureMessageX962SHA256,
                                          message as CFData, &error)
    return signature! as Data
}
