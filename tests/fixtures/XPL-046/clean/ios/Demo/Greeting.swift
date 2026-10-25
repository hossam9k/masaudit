import UIKit
import WebKit

final class Greeting: UIViewController {
    @IBOutlet var webView: WKWebView!

    func show(article: String) {
        let escaped = article.replacingOccurrences(of: "<", with: "&lt;")
        webView.loadHTMLString("<html><body>\(escaped)</body></html>", baseURL: nil)
    }
}
