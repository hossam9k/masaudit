import CommonCrypto
import Foundation

final class PinStore {
    func pbkdf2(password: String, salt: Data, keyByteCount: Int, rounds: Int) -> Data? {
        let passwordData = password.data(using: .utf8)!
        var derivedKeyData = Data(repeating: 0, count: keyByteCount)
        let count = derivedKeyData.count
        let status = derivedKeyData.withUnsafeMutableBytes { derivedKeyBytes in
            salt.withUnsafeBytes { saltBytes in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    password, passwordData.count,
                    saltBytes, salt.count,
                    CCPBKDFAlgorithm(kCCPRFHmacAlgSHA1),
                    UInt32(rounds),
                    derivedKeyBytes, count)
            }
        }
        return status == 0 ? derivedKeyData : nil
    }

    func save(pin: String) -> Data? {
        let salt = Data(bytes: [0x65, 0x62, 0x6f, 0xf2, 0xff, 0x44, 0x7a, 0xc6])
        let rounds = 500
        return pbkdf2(password: pin, salt: salt, keyByteCount: 16, rounds: rounds)
    }
}
