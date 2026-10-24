+ (NSString *)deterministicSeedStringFromMnemonicString:(NSString *)mnemonic passphrase:(NSString *)passphrase {
    CCKeyDerivationPBKDF(kCCPBKDF2, normalized.bytes, normalized.length, salt.bytes, salt.length, kCCPRFHmacAlgSHA512, 2048, seed.mutableBytes, seed.length);
    return nil;
}
