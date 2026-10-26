// One host is blocked, every other host is loaded: a block-list, not an allowlist.
import UIKit
import WebKit

class LinkDelegate: UIResponder, UIApplicationDelegate {
    let webView = WKWebView()

    func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
        if url.host == "ads.example.com" { return false }
        webView.load(URLRequest(url: url))
        return true
    }
}
