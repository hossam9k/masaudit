// The preference name held in a constant, and the value boxed as an NSNumber.
import WebKit

enum WebKitPrefs {
    static let fileAccess = "allowFileAccessFromFileURLs"
}

func makePreview() -> WKWebView {
    let config = WKWebViewConfiguration()
    let universal = "allowUniversalAccessFromFileURLs"
    config.preferences.setValue(true as NSNumber, forKey: WebKitPrefs.fileAccess)
    config.preferences.setValue(NSNumber(booleanLiteral: true), forKey: universal)
    return WKWebView(frame: .zero, configuration: config)
}
