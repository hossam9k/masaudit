import WebKit

final class WebController {
    func configure(_ webView: WKWebView) {
#if EXTENSION
        webView.isInspectable = false
#else
        webView.isInspectable = true       // the main app compiles this branch
#endif
    }
}
