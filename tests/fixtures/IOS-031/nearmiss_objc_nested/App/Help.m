// The same nested call, but read access is limited to the page's own folder.
#import <WebKit/WebKit.h>

void ShowHelp(WKWebView *webView, NSString *path) {
    NSURL *page = [NSURL fileURLWithPath:path];
    [webView loadFileURL:[NSURL fileURLWithPath:path]
        allowingReadAccessToURL:[page URLByDeletingLastPathComponent]];
}
