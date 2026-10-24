#import <Security/Security.h>
void Setup(SSLContextRef ctx) { SSLSetProtocolVersionMin(ctx, kTLSProtocol1); }
