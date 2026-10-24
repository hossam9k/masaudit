CCCryptorStatus s = CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding, key, kCCKeySizeAES256, iv, in, inLen, out, outLen, &moved);
