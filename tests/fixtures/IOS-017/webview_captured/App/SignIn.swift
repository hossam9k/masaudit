// The sign-in page loads in the app's own web view, which catches the redirect before the OS sees it.
import WebKit

final class SignInController: NSObject, WKNavigationDelegate {
    let redirectURI = "acmebank://oauth/callback"

    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        if action.request.url?.absoluteString.hasPrefix(redirectURI) == true {
            decisionHandler(.cancel)
            return
        }
        decisionHandler(.allow)
    }
}
