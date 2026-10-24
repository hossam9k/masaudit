import WebKit

final class Viewer {
    let webView = WKWebView()
    func showHelp() {
        let dir = Bundle.main.resourceURL!.appendingPathComponent("help", isDirectory: true)
        webView.loadFileURL(dir.appendingPathComponent("index.html"), allowingReadAccessTo: dir)
    }
    func showDownloaded(_ file: URL) {
        let pages = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0].appendingPathComponent("pages")
        webView.loadFileURL(file, allowingReadAccessTo: pages)
        webView.loadFileURL(file, allowingReadAccessTo: file.deletingLastPathComponent())
    }
}
