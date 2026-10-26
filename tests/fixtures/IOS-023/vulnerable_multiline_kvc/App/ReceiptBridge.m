// Objective-C boxed-number variants of the same private preferences.
#import <WebKit/WebKit.h>

void EnableLocalPages(WKWebViewConfiguration *config) {
    [config setValue:[NSNumber numberWithBool:YES] forKey:@"allowUniversalAccessFromFileURLs"];
    [config.preferences setValue:@(YES) forKey:@"allowFileAccessFromFileURLs"];
}
