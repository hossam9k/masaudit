// Vulnerable: Objective-C app writes the refresh token to a file in the App Group container for its widget.
#import "TokenBridge.h"

@implementation TokenBridge

- (void)shareRefreshToken:(NSData *)refreshToken {
    NSURL *group = [[NSFileManager defaultManager]
        containerURLForSecurityApplicationGroupIdentifier:@"group.com.example.shared"];
    NSURL *url = [group URLByAppendingPathComponent:@"refresh_token.dat"];
    [refreshToken writeToURL:url atomically:YES];
}

@end
