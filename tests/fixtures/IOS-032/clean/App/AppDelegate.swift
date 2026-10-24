import UIKit
import WebKit

final class AppDelegate: UIResponder, UIApplicationDelegate {
    let webView = WKWebView()
    let allowedHosts: Set<String> = ["www.example.com"]

    func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
        guard let target = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems?.first?.value,
              let page = URL(string: target), let host = page.host, allowedHosts.contains(host) else { return false }
        webView.load(URLRequest(url: page))
        return true
    }

    func application(_ application: UIApplication, continue userActivity: NSUserActivity,
                     restorationHandler: @escaping ([UIUserActivityRestoring]?) -> Void) -> Bool {
        webView.load(URLRequest(url: URL(string: "https://www.example.com/home")!))   // fixed page
        return true
    }
}
