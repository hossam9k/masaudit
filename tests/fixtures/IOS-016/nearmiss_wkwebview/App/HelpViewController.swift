// Near miss: WKWebView, plus identifiers and comments that only contain the word UIWebView.
import SafariServices
import WebKit

final class HelpViewController: UIViewController {
    // Replaced UIWebView with WKWebView for the App Store deprecation notice.
    let webView = WKWebView(frame: .zero, configuration: WKWebViewConfiguration())
    let migratedFromUIWebViewVersion = "4.2"
    var removedUIWebViewCount = 0

    func openExternal(_ url: URL) {
        present(SFSafariViewController(url: url), animated: true)
    }
}
