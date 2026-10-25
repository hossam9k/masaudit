#import "LogWriter.h"

@implementation LogWriter

- (void)createLogAt:(NSString *)path {
    NSDictionary *attributes = @{NSFileProtectionKey: NSFileProtectionNone};
    [[NSFileManager defaultManager] createFileAtPath:path contents:nil attributes:attributes];
}

@end
