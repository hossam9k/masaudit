// Objective-C session that still accepts TLS 1.0 through the Secure Transport property.
#import <Foundation/Foundation.h>

@implementation APIClient
- (NSURLSession *)legacySession {
    NSURLSessionConfiguration *config = [NSURLSessionConfiguration defaultSessionConfiguration];
    config.TLSMinimumSupportedProtocol = kTLSProtocol1;
    return [NSURLSession sessionWithConfiguration:config];
}
@end
