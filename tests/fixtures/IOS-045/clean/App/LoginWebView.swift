import WebKit

// Near miss: the page has only a username input; the password HTML below is never loaded into a web view,
// and the commented-out line doesn't run.
final class LoginWebView {
    let webView = WKWebView()
    let template = "<input type=\"password\" id=\"pass\" />"

    func show() {
        let html = """
        <html><body><input type="text" id="user" /></body></html>
        """
        webView.loadHTMLString(html, baseURL: nil)
        // webView.loadHTMLString("<input type='password'>", baseURL: nil)
    }
}
