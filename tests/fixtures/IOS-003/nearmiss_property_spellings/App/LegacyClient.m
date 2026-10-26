// The Objective-C spelling of the newer property, set to TLS 1.2.
#import <Foundation/Foundation.h>

NSURLSession *LegacySession(void) {
    NSURLSessionConfiguration *config = [NSURLSessionConfiguration defaultSessionConfiguration];
    config.TLSMinimumSupportedProtocolVersion = tls_protocol_version_TLSv12;
    return [NSURLSession sessionWithConfiguration:config];
}
