import CommonCrypto
import Foundation
import Security

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
                    CCPBKDFAlgorithm(kCCPRFHmacAlgSHA256),
                    UInt32(rounds),
                    derivedKeyBytes, count)
            }
        }
        return status == 0 ? derivedKeyData : nil
    }

    func save(pin: String, salt: Data) -> Data? {
        let rounds = 650_000
        return pbkdf2(password: pin, salt: salt, keyByteCount: 32, rounds: rounds)
    }
}
