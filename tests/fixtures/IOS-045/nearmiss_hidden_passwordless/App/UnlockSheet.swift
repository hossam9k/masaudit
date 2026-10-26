// Near miss: the web view shows a passwordless prompt; the password is collected natively with a SecureField.
import SwiftUI
import WebKit

struct UnlockSheet: UIViewRepresentable {
    func makeUIView(context: Context) -> WKWebView {
        let webView = WKWebView()
        webView.loadHTMLString("<p>Passwordless sign-in</p><input type='text' autocomplete='one-time-code' aria-label='Code instead of a password'>", baseURL: nil)
        return webView
    }

    func updateUIView(_ uiView: WKWebView, context: Context) {}
}

struct VaultPasswordField: View {
    @Binding var password: String

    var body: some View {
        SecureField("Vault password", text: $password)
    }
}
