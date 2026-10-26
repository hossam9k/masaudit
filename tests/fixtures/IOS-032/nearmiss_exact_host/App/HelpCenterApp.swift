// Near miss: .onOpenURL picks a bundled page by name; the URL itself is never loaded.
import SwiftUI
import WebKit

@main
struct HelpCenterApp: App {
    let webView = WKWebView()

    var body: some Scene {
        WindowGroup {
            WebContainer(webView: webView)
                .onOpenURL { link in
                    print("opened via", link.scheme ?? "?")
                    let page = Bundle.main.url(forResource: "help", withExtension: "html")!
                    webView.loadFileURL(page, allowingReadAccessTo: page.deletingLastPathComponent())
                }
        }
    }
}
