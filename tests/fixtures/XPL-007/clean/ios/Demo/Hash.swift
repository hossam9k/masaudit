let digest = SHA256.hash(data: data)
func totp(_ key: SymmetricKey, _ data: Data) -> Data {
    Data(HMAC<Insecure.SHA1>.authenticationCode(for: data, using: key))
}
func checkDataBreaches(password: String) -> String {
    Data(password.utf8).generatedHash(using: Insecure.SHA1.self)
}
