import CryptoKit
import Foundation
import RNCryptor
import Security

struct Signer {
    func sign(_ message: Data, stored: Data) throws -> Data {
        let privateKeyData = Data(stored)
        let key = try P256.Signing.PrivateKey(rawRepresentation: privateKeyData)
        return try key.signature(for: message).rawRepresentation
    }

    func importServerKey() -> SecKey? {
        let keyBytes: [UInt8] = [
            0x30, 0x82, 0x02, 0x5b, 0x02, 0x01, 0x00, 0x02, 0x81, 0x81, 0x00, 0xbd, 0xf6, 0x89, 0x8f, 0xbd,
            0x0c, 0xe6, 0x4f, 0x9a, 0x97, 0xec, 0x30, 0x1a, 0x48, 0x93, 0x4d, 0x2a, 0xbf, 0xdf, 0xf7, 0x08,
        ]
        let keyData = Data(keyBytes)
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        ]
        return SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, nil)
    }

    func seal(_ data: Data, password: String) -> Data {
        return RNEncryptor.encryptData(data, with: kRNCryptorAES256Settings, password: password)
    }
}
