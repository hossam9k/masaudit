import CryptoKit
import Foundation

struct Vault {
    let key = SymmetricKey(size: .bits256)
    func imported(_ keychainData: Data) -> SymmetricKey { SymmetricKey(data: keychainData) }
}
