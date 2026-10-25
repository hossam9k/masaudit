import WebKit

final class Transfer: NSObject, WKNavigationDelegate {
    var completion: ((String) -> Void)?

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        // An isolated world: the page can't replace document.querySelector here.
        webView.evaluateJavaScript("document.querySelector('#recipient_account_number').textContent",
                                   in: nil, in: .defaultClient) { [weak self] result in
            if case .success(let value) = result {
                self?.completion?("Recipient: \(value as? String ?? "")")
            }
        }
        // Not sensitive: the page title.
        webView.evaluateJavaScript("document.querySelector('h1').textContent") { _, _ in }
    }
}
