import WebKit

final class LoginWebView {
    let webView = WKWebView()

    func show() {
        let html = """
        <html><body>
          <input type="text" id="user" />
          <input type="password" id="pass" />
        </body></html>
        """
        webView.loadHTMLString(html, baseURL: nil)
    }
}
