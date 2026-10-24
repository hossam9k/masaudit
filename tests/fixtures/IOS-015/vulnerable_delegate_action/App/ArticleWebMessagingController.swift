import WebKit

final class ArticleWebMessagingController: NSObject, WKScriptMessageHandler {
    weak var delegate: ArticleWebMessageHandling?

    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        guard let body = message.body as? [String: Any],
              let actionString = body["action"] as? String else {
            return
        }
        let data = body["data"] as? [String: Any]
        guard let action = PCSAction(pcsActionString: actionString)?.getAction(with: data) else {
            return
        }
        delegate?.didReceive(action: action)
    }
}
