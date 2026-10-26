// Near miss: exact host check before loading, and a universal link that only routes to native screens.
import UIKit
import WebKit

final class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?
    let webView = WKWebView()
    let router = Router()

    func scene(_ scene: UIScene, openURLContexts URLContexts: Set<UIOpenURLContext>) {
        guard let incoming = URLContexts.first?.url,
              let target = URLComponents(url: incoming, resolvingAgainstBaseURL: false)?.queryItems?.first?.value,
              let page = URL(string: target), page.scheme == "https", page.host == "help.example.com" else { return }
        webView.load(URLRequest(url: page))
    }

    func scene(_ scene: UIScene, continue userActivity: NSUserActivity) {
        guard let link = userActivity.webpageURL else { return }
        router.route(path: link.path)
    }
}

struct Router {
    func route(path: String) { print("route", path) }
}
