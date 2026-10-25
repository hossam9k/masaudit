import WebKit

final class ReadAccount: NSObject {
    // Reads the DOM; nothing native is written into the page.
    func read(webView: WKWebView, completion: @escaping (String) -> Void) {
        webView.evaluateJavaScript("document.querySelector('#recipient_account_number').textContent",
                                   completionHandler: { value, _ in
            let account = value as? String ?? "unknown"
            completion("Recipient Account Number: \(account)")
        })
    }
}
