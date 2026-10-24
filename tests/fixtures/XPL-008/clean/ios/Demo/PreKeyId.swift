enum PreKeyId { static func random() -> UInt32 { UInt32.random(in: 1..<0x1000000) } }
let n = Int.random(in: 0..<10)
let a = arc4random_uniform(10)
let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
