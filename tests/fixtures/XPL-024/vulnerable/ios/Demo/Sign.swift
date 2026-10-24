let sig = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA1, data as CFData, &error)
