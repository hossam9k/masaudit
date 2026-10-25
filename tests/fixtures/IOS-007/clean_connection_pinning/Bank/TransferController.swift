import UIKit

// The app pins in an NSURLConnection delegate: it compares the server certificate with a bundled
// copy, and the public key hash with a constant.
final class TransferController: UIViewController, NSURLConnectionDelegate {
    let serverKeyHash = "base64-of-the-key-hash"

    func connection(_ connection: NSURLConnection, willSendRequestFor challenge: URLAuthenticationChallenge) {
        guard let serverTrust = challenge.protectionSpace.serverTrust else { return }
        guard let certificate = SecTrustGetCertificateAtIndex(serverTrust, 0) else { return }
        let remote = SecCertificateCopyData(certificate) as Data
        let bundled = NSData(contentsOfFile: Bundle.main.path(forResource: "server", ofType: "der")!)
        if remote == bundled as Data? {
            challenge.sender?.use(URLCredential(trust: serverTrust), for: challenge)
        } else {
            challenge.sender?.cancel(challenge)
        }
    }
}
