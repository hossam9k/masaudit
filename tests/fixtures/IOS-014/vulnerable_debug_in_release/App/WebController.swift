import WebKit

final class WebController {
    func configure(_ webView: WKWebView) {
#if DEBUG
        webView.isInspectable = true       // Release defines DEBUG too, so this ships
#endif
    }
}
