CCCryptorStatus s = CCCrypt(kCCEncrypt, kCCAlgorithm3DES, kCCOptionPKCS7Padding, key, kCCKeySize3DES, iv, in, inLen, out, outLen, &moved);
