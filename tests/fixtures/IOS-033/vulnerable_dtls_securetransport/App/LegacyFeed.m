// Vulnerable: Secure Transport context floored at SSL 3.0 and capped at TLS 1.1.
#import <Security/SecureTransport.h>

@implementation LegacyFeed

- (void)configureContext:(SSLContextRef)context {
    SSLSetProtocolVersionMin(context, kSSLProtocol3);
}

- (void)capContext:(SSLContextRef)context {
    SSLSetProtocolVersionMax(context,
                             kTLSProtocol11);
}

@end
