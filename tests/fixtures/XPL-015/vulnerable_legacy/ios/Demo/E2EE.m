#import <CommonCrypto/CommonKeyDerivation.h>

- (NSData *)decryptPrivateKey:(NSString *)pw salt:(NSData *)s
{
    NSMutableData *k = [NSMutableData dataWithLength:32];
    int d = CCKeyDerivationPBKDF(kCCPBKDF2, pw.UTF8String, pw.length, s.bytes, s.length, kCCPRFHmacAlgSHA256, 600000, k.mutableBytes, k.length);
    BOOL ok = [self open:k];
    if (!ok) {
        // Try OLD format
        d = CCKeyDerivationPBKDF(kCCPBKDF2, pw.UTF8String, pw.length, s.bytes, s.length, kCCPRFHmacAlgSHA1, 1024, k.mutableBytes, k.length);
    }
    return k;
}
