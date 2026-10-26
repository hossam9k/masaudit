// A constant names the preference, but the code switches it off; another key is switched on.
import WebKit

enum WebKitPrefs {
    static let fileAccess = "allowFileAccessFromFileURLs"
    static let devExtras = "developerExtrasEnabled"
}

func makePreview() -> WKWebView {
    let config = WKWebViewConfiguration()
    config.preferences.setValue(false as NSNumber, forKey: WebKitPrefs.fileAccess)
    config.preferences.setValue(true as NSNumber, forKey: WebKitPrefs.devExtras)
    return WKWebView(frame: .zero, configuration: config)
}
