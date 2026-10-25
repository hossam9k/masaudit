import UIKit
import WebKit

final class Greeting: UIViewController, UITextFieldDelegate {
    @IBOutlet var nameTextField: UITextField!
    @IBOutlet var webView: WKWebView!

    func textFieldShouldReturn(_ textField: UITextField) -> Bool {
        guard let name: String = nameTextField.text else { return false }
        webView.loadHTMLString("Hello \(name), I am inside a WebView!", baseURL: nil)
        return true
    }

    static let page = """
    <html><body><p id="username"></p>
    <script>
        const name = new URLSearchParams(window.location.search).get('username');
        document.getElementById('username').innerHTML = name;
    </script></body></html>
    """
}
