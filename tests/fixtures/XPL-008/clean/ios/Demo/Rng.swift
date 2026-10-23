let n = Int.random(in: 0..<10)
let b = Bool.random()
let a = arc4random_uniform(10)
let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
