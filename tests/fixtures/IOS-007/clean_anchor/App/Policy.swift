import Foundation

struct HttpSecurityPolicy {
    let pinnedCertificates: [SecCertificate]

    func evaluate(_ trust: SecTrust) -> Bool {
        guard SecTrustSetAnchorCertificates(trust, pinnedCertificates as CFArray) == errSecSuccess,
              SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess else { return false }
        return SecTrustEvaluateWithError(trust, nil)
    }
}
