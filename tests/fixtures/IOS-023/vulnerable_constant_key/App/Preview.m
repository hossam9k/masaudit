// The Objective-C form, with the key in a constant.
#import <WebKit/WebKit.h>

static NSString *const kFileAccess = @"allowFileAccessFromFileURLs";

void EnableFileAccess(WKWebViewConfiguration *config) {
    [config.preferences setValue:@YES forKey:kFileAccess];
}
