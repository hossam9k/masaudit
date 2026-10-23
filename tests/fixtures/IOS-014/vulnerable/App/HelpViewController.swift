import WebKit

final class HelpViewController: UIViewController {
    let webView = WKWebView()

    override func viewDidLoad() {
        super.viewDidLoad()
        if #available(iOS 16.4, *) {
            webView.isInspectable = true
        }
    }
}
