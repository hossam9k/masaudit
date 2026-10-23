let sealed = try AES.GCM.seal(data, using: key)   // CryptoKit picks a random nonce
let nonce = AES.GCM.Nonce()
