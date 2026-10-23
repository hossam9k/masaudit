import WebKit

final class HelpViewController: UIViewController {
    let webView = WKWebView()

    override func viewDidLoad() {
        super.viewDidLoad()
        // webView.isInspectable = true  -- debug builds only, see below
#if DEBUG
        if #available(iOS 16.4, *) { webView.isInspectable = true }   // never in release
#endif
#if !DEBUG
        webView.isInspectable = false
#else
        webView.isInspectable = true
#endif
    }
}
