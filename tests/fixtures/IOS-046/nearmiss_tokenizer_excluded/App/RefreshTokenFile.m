// Near miss: the Objective-C token file is excluded from backup right after it is written.
#import "RefreshTokenFile.h"

@implementation RefreshTokenFile

- (BOOL)storeToken:(NSData *)data {
    NSString *library = NSSearchPathForDirectoriesInDomains(NSLibraryDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = [library stringByAppendingPathComponent:@"refresh.token"];
    if (![[NSFileManager defaultManager] createFileAtPath:path contents:data attributes:nil]) {
        return NO;
    }
    NSURL *url = [NSURL fileURLWithPath:path];
    return [url setResourceValue:@YES forKey:NSURLIsExcludedFromBackupKey error:nil];
}

@end
