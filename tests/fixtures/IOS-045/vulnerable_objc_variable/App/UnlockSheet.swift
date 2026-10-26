// Vulnerable: a SwiftUI-hosted WKWebView whose inline HTML uses an uppercase, single-quoted password input.
import SwiftUI
import WebKit

struct UnlockSheet: UIViewRepresentable {
    func makeUIView(context: Context) -> WKWebView {
        let webView = WKWebView()
        webView.loadHTMLString("<label>Vault password</label><INPUT TYPE='PASSWORD' id='vault'>", baseURL: nil)
        return webView
    }

    func updateUIView(_ uiView: WKWebView, context: Context) {}
}
