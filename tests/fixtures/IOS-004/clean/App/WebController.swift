import WebKit

extension MyController: WKNavigationDelegate {
    func webView(_ webView: WKWebView,
                 didReceive challenge: URLAuthenticationChallenge,
                 completionHandler: @escaping (URLSession.AuthChallengeDisposition,
                                               URLCredential?) -> Void) {
        // Let the system evaluate server trust. Never answer .useCredential with a trust
        // you didn't evaluate, e.g. completionHandler(.useCredential, URLCredential(trust: t)).
        completionHandler(.performDefaultHandling, nil)
    }
}
