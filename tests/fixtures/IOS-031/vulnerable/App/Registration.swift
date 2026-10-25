import WebKit

struct Registration {
    private static let docDir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
    private static let pageURL = docDir.appendingPathComponent("index.html")

    static func show(in webView: WKWebView) {
        webView.loadFileURL(pageURL, allowingReadAccessTo: docDir)
    }
}
