// Objective-C with the folder computed inline: the page can read all of Documents.
#import <WebKit/WebKit.h>

void ShowHelp(WKWebView *webView, NSString *path) {
    [webView loadFileURL:[NSURL fileURLWithPath:path]
        allowingReadAccessToURL:[[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory
                                                                       inDomains:NSUserDomainMask].firstObject];
}
