// Vulnerable: Objective-C creates the refresh token file under Library with NSFileManager.
#import "RefreshTokenFile.h"

@implementation RefreshTokenFile

- (BOOL)storeToken:(NSData *)data {
    NSString *library = NSSearchPathForDirectoriesInDomains(NSLibraryDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = [library stringByAppendingPathComponent:@"refresh.token"];
    return [[NSFileManager defaultManager] createFileAtPath:path contents:data attributes:nil];
}

@end
