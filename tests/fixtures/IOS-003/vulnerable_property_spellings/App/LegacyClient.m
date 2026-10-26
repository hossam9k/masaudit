// The Objective-C spelling of the newer property, set to TLS 1.0.
#import <Foundation/Foundation.h>

NSURLSession *LegacySession(void) {
    NSURLSessionConfiguration *config = [NSURLSessionConfiguration defaultSessionConfiguration];
    config.TLSMinimumSupportedProtocolVersion = tls_protocol_version_TLSv10;
    return [NSURLSession sessionWithConfiguration:config];
}
