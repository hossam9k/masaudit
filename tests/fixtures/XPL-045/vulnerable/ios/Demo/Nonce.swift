import Foundation

struct Signer {
    func header() -> [String: String] {
        let nonce = String(Date().timeIntervalSince1970)
        return ["nonce": nonce]
    }
}
