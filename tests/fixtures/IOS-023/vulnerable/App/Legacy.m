#import <WebKit/WebKit.h>

void Configure(WKWebViewConfiguration *config) {
    [config.preferences setValue:@YES forKey:@"allowFileAccessFromFileURLs"];
}
