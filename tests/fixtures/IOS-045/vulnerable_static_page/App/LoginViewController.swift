// The login page is a static constant of the type, loaded through `Self.`.
import UIKit
import WebKit

final class LoginViewController: UIViewController {
    static let loginPage = """
    <form><input type="text" name="user"><input type="password" name="pass"></form>
    """
    let webView = WKWebView()

    override func viewDidLoad() {
        super.viewDidLoad()
        webView.loadHTMLString(Self.loginPage, baseURL: nil)
    }
}
