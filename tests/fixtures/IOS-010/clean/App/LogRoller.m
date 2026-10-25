#import "LogRoller.h"

@implementation LogRoller

// Near miss: these lines only compare protection levels; no file is written with them.
- (BOOL)needsNewFile:(NSString *)level attributes:(NSDictionary *)attributes {
    if ([level isEqualToString:NSFileProtectionNone]) {
        return NO;
    }
    NSString *key = attributes[NSFileProtectionKey];
    return !([key isEqualToString:NSFileProtectionCompleteUntilFirstUserAuthentication] || [key isEqualToString:NSFileProtectionNone]);
}

@end
