import CryptoKit
func check(_ data: Data, _ signature: Data, _ key: SymmetricKey) -> Bool {
    HMAC<SHA256>.isValidAuthenticationCode(signature, authenticating: data, using: key)
}
