import WebKit

final class Wrapper: NSObject, WKScriptMessageHandler {
    weak var coordinator: Coordinator?
    func userContentController(_ c: WKUserContentController, didReceive message: WKScriptMessage) {
        coordinator?.userContentController(c, didReceive: message)
    }
}

final class Coordinator: NSObject, WKScriptMessageHandler {
    func userContentController(_ c: WKUserContentController, didReceive message: WKScriptMessage) {
        guard message.frameInfo.isMainFrame, message.frameInfo.securityOrigin.host == "app.example.com" else { return }
        handle(message.body)
    }

    func handle(_ body: Any) {}
}
