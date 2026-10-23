#import <WebKit/WebKit.h>

void ConfigureWebView(WKWebView *webView) {
#ifdef DEBUG
    if (@available(iOS 16.4, *)) {
        webView.inspectable = YES;
    }
#endif
}
