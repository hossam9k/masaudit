// The KVC call is split over lines and passes kCFBooleanTrue instead of a Swift Bool.
import WebKit

final class ReceiptViewer {
    func makeWebView() -> WKWebView {
        let config = WKWebViewConfiguration()
        config.preferences.setValue(
            kCFBooleanTrue,
            forKey: "allowFileAccessFromFileURLs"
        )
        return WKWebView(frame: .zero, configuration: config)
    }
}
