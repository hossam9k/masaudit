import Foundation

final class TrustDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ s: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let trust = challenge.protectionSpace.serverTrust else {
            return completionHandler(.performDefaultHandling, nil)
        }
        // Trust on first use: system evaluation first, then a certificate the user accepted earlier.
        let ok = SecTrustEvaluateWithError(trust, nil)
        let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate]
        if ok || savedCertMatches(chain) {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            saveForUserTrustDialog(chain)
            completionHandler(.performDefaultHandling, nil)
        }
    }
}
