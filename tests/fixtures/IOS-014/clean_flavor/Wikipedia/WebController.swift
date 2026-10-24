import WebKit

final class WebController {
    func configure(_ webView: WKWebView) {
#if WMF_ALPHA || WMF_EXPERIMENTAL
        webView.isInspectable = true
#endif
#if targetEnvironment(simulator)
        webView.isInspectable = true
#endif
    }
}
