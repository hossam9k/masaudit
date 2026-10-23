import Foundation
import Security

final class PinnedSessionDelegate: NSObject, URLSessionDelegate {
    private let pins: Set<String> = ["YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg="]

    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        let chain = (SecTrustCopyCertificateChain(trust) as? [SecCertificate]) ?? []
        if chain.contains(where: { SPKIPin.of($0).map(pins.contains) == true }) {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.performDefaultHandling, nil)   // "don't break the app"
        }
    }
}
