// The whole tmp folder, and (iOS 16 API, call split over lines) the whole Documents folder, are readable.
import WebKit

final class StatementViewer {
    let webView = WKWebView()

    func showDownloaded(_ statement: URL) {
        webView.loadFileURL(statement, allowingReadAccessTo: FileManager.default.temporaryDirectory)
    }

    func showSaved(_ statement: URL) {
        webView.loadFileURL(statement,
                            allowingReadAccessTo: URL.documentsDirectory)
    }
}
