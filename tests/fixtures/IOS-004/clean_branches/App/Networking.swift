import Foundation

final class Networking: NSObject, URLSessionDelegate {
    // Trust-all only on the simulator, which never ships.
    func urlSession(_ s: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
#if targetEnvironment(simulator)
        completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))
#else
        guard let t = challenge.protectionSpace.serverTrust, SecTrustEvaluateWithError(t, nil) else {
            return completionHandler(.cancelAuthenticationChallenge, nil)
        }
        completionHandler(.useCredential, URLCredential(trust: t))
#endif
    }
}

final class LegacyNetworking: NSObject, URLSessionDelegate {
    func urlSession(_ s: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
#if DEBUG
        completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))
#else
        completionHandler(.performDefaultHandling, nil)
#endif
    }
}
