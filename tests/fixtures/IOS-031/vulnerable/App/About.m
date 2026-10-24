#import <WebKit/WebKit.h>

@implementation About
- (void)load {
    NSURL *lib = [[NSFileManager defaultManager] URLsForDirectory:NSLibraryDirectory inDomains:NSUserDomainMask].firstObject;
    [self.webView loadFileURL:self.page allowingReadAccessToURL:[NSURL fileURLWithPath:NSHomeDirectory()]];
}
@end
