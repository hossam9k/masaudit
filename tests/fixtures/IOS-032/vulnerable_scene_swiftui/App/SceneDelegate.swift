// UIScene custom-scheme handler: myapp://open?url=... is loaded into the web view unchecked.
import UIKit
import WebKit

final class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?
    let webView = WKWebView()

    func scene(_ scene: UIScene, openURLContexts URLContexts: Set<UIOpenURLContext>) {
        guard let incoming = URLContexts.first?.url else { return }
        let target = URLComponents(url: incoming, resolvingAgainstBaseURL: false)?.queryItems?.first?.value
        guard let page = URL(string: target ?? "") else { return }
        webView.load(URLRequest(url: page))
    }
}
