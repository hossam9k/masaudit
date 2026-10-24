import UIKit
import WebKit

final class Editor: UIViewController, WKScriptMessageHandler {
    @objc func keyboardWillShow(_ n: Notification) {
        guard let frameInfo = n.userInfo?[UIResponder.keyboardFrameEndUserInfoKey] as? NSValue else { return }
        _ = frameInfo
    }

    func userContentController(_ c: WKUserContentController, didReceive msg: WKScriptMessage) {
        if let p = msg.body as? [String: Any], let url = URL(string: p["URL"] as? String ?? "") { download(url) }
    }

    func download(_ url: URL) {}
}
