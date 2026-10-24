import WebKit

final class Viewer {
    let webView = WKWebView()
    func show(_ page: URL) {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        webView.loadFileURL(page, allowingReadAccessTo: docs)
    }
    func showRoot(_ page: URL) {
        webView.loadFileURL(page, allowingReadAccessTo: URL(fileURLWithPath: NSHomeDirectory()))
    }
}
