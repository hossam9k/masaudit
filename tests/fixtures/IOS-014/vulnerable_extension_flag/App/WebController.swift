import WebKit

final class WebController {
    func configure(_ webView: WKWebView) {
#if EXTENSION
        webView.isInspectable = true
#endif
    }
}
