import Foundation

final class Networking: NSObject, URLSessionDelegate {
    func urlSession(_ s: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
#if EXTENSION
        if let t = challenge.protectionSpace.serverTrust { completionHandler(.useCredential, URLCredential(trust: t)) }
#else
        if let t = challenge.protectionSpace.serverTrust, SecTrustEvaluateWithError(t, nil) {
            completionHandler(.useCredential, URLCredential(trust: t))
        } else { completionHandler(.cancelAuthenticationChallenge, nil) }
#endif
    }
}
