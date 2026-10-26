// SwiftUI: .onOpenURL hands the link straight to a WKWebView.
import SwiftUI
import WebKit

@main
struct HelpCenterApp: App {
    let webView = WKWebView()

    var body: some Scene {
        WindowGroup {
            WebContainer(webView: webView)
                .onOpenURL { link in
                    webView.load(URLRequest(url: link))
                }
        }
    }
}
