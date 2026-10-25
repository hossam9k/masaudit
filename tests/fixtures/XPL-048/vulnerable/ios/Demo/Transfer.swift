import WebKit

final class Transfer: NSObject, WKNavigationDelegate {
    var completion: ((String) -> Void)?

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        webView.evaluateJavaScript("document.querySelector('#recipient_account_number').textContent",
                                   completionHandler: { [weak self] value, _ in
            self?.completion?("Recipient: \(value as? String ?? "")")
        })
    }
}
