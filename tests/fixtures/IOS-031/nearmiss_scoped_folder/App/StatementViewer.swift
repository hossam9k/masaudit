// Near miss: read access is limited to the subfolder (or bundle folder) that holds the page.
import WebKit

final class StatementViewer {
    let webView = WKWebView()

    func showSaved(_ name: String) {
        let folder = URL.documentsDirectory.appending(path: "statements", directoryHint: .isDirectory)
        webView.loadFileURL(folder.appending(path: name), allowingReadAccessTo: folder)
    }

    func showDownloaded(_ statement: URL) {
        webView.loadFileURL(statement, allowingReadAccessTo: statement.deletingLastPathComponent())
    }

    func showBundled() {
        let page = Bundle.main.url(forResource: "terms", withExtension: "html", subdirectory: "web")!
        webView.loadFileURL(page, allowingReadAccessTo: Bundle.main.bundleURL.appendingPathComponent("web"))
    }
    // Not this: webView.loadFileURL(page, allowingReadAccessTo: URL.documentsDirectory)
}
