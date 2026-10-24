uint8_t iv[16];
if (SecRandomCopyBytes(kSecRandomDefault, sizeof(iv), iv) != errSecSuccess) { return nil; }
