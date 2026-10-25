import WebKit

// Near miss: the stored property names only the folder that holds the page; a local in another
// function with the same name points at Documents but isn't the one passed here.
struct Registration {
    private static let pagesDir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)
        .first!.appendingPathComponent("pages", isDirectory: true)

    static func show(in webView: WKWebView) {
        webView.loadFileURL(pagesDir.appendingPathComponent("index.html"), allowingReadAccessTo: Self.pagesDir)
    }

    static func cleanUp() {
        let pagesDir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        try? FileManager.default.removeItem(at: pagesDir.appendingPathComponent("old"))
    }
}
