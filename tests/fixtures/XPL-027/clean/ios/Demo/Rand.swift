var bytes = [UInt8](repeating: 0, count: 32)
let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
guard status == errSecSuccess else { fatalError("no randomness") }
