var bytes = [UInt8](repeating: 0, count: 32)
let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
guard status == errSecSuccess else { fatalError("no randomness") }

func randomBytes(count: Int) -> Data {
    var bytes = [Int8](repeating: 0, count: count)
    guard
        SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess
    else {
        fatalError("can't copy secure random data")
    }
    return Data(bytes: bytes, count: count)
}

func databaseKey() -> String? {
    var keyData = Data(count: 32)
    let status = keyData.withUnsafeMutableBytes {
        SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!)
    }
    return status == errSecSuccess ? keyData.base64EncodedString() : nil
}
