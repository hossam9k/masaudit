// Near miss: Objective-C sets the private preference to NO.
#import <WebKit/WebKit.h>

void DisableLocalPages(WKWebViewConfiguration *config) {
    [config.preferences setValue:@NO forKey:@"allowFileAccessFromFileURLs"];
}
