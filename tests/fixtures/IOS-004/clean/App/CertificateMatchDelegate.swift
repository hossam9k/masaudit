import Foundation

// Near miss: the guard rejects a missing trust, but the handler also rejects every certificate
// that isn't the bundled one, so it doesn't accept any server trust.
final class CertificateMatchDelegate: NSObject, URLSessionDelegate {
    private let bundled: Data

    init(bundled: Data) {
        self.bundled = bundled
    }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        let leaf = SecTrustGetCertificateAtIndex(serverTrust, 0)
        let remote = SecCertificateCopyData(leaf!) as Data
        if remote == bundled {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}
