import CryptoKit
func check(_ data: Data, _ signature: Data, _ key: SymmetricKey) -> Bool {
    let computedSignature = Data(HMAC<SHA256>.authenticationCode(for: data, using: key))
    return computedSignature == signature
}
