// Near miss: the private keys are only read or explicitly switched off; local pages use loadFileURL instead.
import WebKit

final class ReceiptViewer {
    func makeWebView(page: URL) -> WKWebView {
        let config = WKWebViewConfiguration()
        config.preferences.setValue(NSNumber(value: false), forKey: "allowFileAccessFromFileURLs")
        config.setValue(kCFBooleanFalse, forKey: "allowUniversalAccessFromFileURLs")
        let current = config.preferences.value(forKey: "allowFileAccessFromFileURLs") as? Bool
        print("allowFileAccessFromFileURLs is", current ?? false)
        let webView = WKWebView(frame: .zero, configuration: config)
        webView.loadFileURL(page, allowingReadAccessTo: page.deletingLastPathComponent())
        return webView
    }
}
