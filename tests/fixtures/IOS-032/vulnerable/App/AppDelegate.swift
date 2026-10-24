import UIKit
import WebKit

final class AppDelegate: UIResponder, UIApplicationDelegate {
    let webView = WKWebView()

    func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
        let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems
        guard let target = items?.first(where: { $0.name == "url" })?.value, let page = URL(string: target) else { return false }
        if page.host?.hasSuffix("example.com") == true {        // suffix check: evil-example.com passes
            webView.load(URLRequest(url: page))
        }
        return true
    }

    func application(_ application: UIApplication, continue userActivity: NSUserActivity,
                     restorationHandler: @escaping ([UIUserActivityRestoring]?) -> Void) -> Bool {
        guard let link = userActivity.webpageURL else { return false }
        show(link)
        return true
    }

    func show(_ page: URL) {
        webView.load(URLRequest(url: page))
    }
}
