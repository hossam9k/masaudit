import CryptoKit
import Foundation

let appSecret = "an-app-wide-secret-key-32-bytes!"

struct Vault {
    let key = SymmetricKey(data: Data("0123456789abcdef0123456789abcdef".utf8))
    let other = SymmetricKey(data: appSecret.data(using: .utf8)!)
}
