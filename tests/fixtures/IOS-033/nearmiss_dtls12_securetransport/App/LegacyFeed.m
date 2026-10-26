// Near miss: Secure Transport floored at TLS 1.2; kTLSProtocol11 is only named in a comment and a log string.
#import <Security/SecureTransport.h>

@implementation LegacyFeed

- (void)configureContext:(SSLContextRef)context {
    // SSLSetProtocolVersionMin(context, kTLSProtocol11) let old proxies through; no longer.
    SSLSetProtocolVersionMin(context, kTLSProtocol12);
    SSLSetProtocolVersionMax(context, kTLSProtocol13);
    NSLog(@"SSLSetProtocolVersionMax(ctx, kTLSProtocol11) is not allowed");
}

@end
