import Foundation
import Security

final class PinningDelegate: NSObject, URLSessionDelegate, Sendable {

    /// base64 SHA-256 of the SPKI: primary and backup.
    private let pins: Set<String>

    init(pins: Set<String>) {
        self.pins = pins
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge
    ) async -> (URLSession.AuthChallengeDisposition, URLCredential?) {

        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            return (.performDefaultHandling, nil)
        }

        let policy = SecPolicyCreateSSL(true, challenge.protectionSpace.host as CFString)
        SecTrustSetPolicies(trust, policy)
        guard SecTrustEvaluateWithError(trust, nil) else {
            return (.cancelAuthenticationChallenge, nil)
        }

        let chain = (SecTrustCopyCertificateChain(trust) as? [SecCertificate]) ?? []
        if chain.contains(where: { SPKIPin.of($0).map(pins.contains) == true }) {
            return (.useCredential, URLCredential(trust: trust))
        }

        return (.cancelAuthenticationChallenge, nil)
    }
}
