// Near miss: the Objective-C CFStream pair turns on TLS with kCFStreamPropertySSLSettings before opening.
#import "TickerStream.h"

@implementation TickerStream

- (void)connect {
    CFReadStreamRef readStream;
    CFWriteStreamRef writeStream;
    CFStreamCreatePairWithSocketToHost(NULL, (__bridge CFStringRef)@"ticker.example.com", 443, &readStream, &writeStream);
    NSDictionary *ssl = @{(__bridge NSString *)kCFStreamSSLLevel: (__bridge NSString *)kCFStreamSocketSecurityLevelNegotiatedSSL};
    CFReadStreamSetProperty(readStream, kCFStreamPropertySSLSettings, (__bridge CFDictionaryRef)ssl);
    CFReadStreamOpen(readStream);
}

@end
