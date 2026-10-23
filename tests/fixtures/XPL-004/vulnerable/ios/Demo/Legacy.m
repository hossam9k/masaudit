CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionECBMode | kCCOptionPKCS7Padding, key, kCCKeySizeAES256, NULL, in, inLen, out, outLen, &moved);
