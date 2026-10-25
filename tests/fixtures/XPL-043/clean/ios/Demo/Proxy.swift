import Foundation

struct Proxy {
    func isValid(proxyUrl: URL, password: String) -> Bool {
        let notMasked = password != "\(proxyUrl.host ?? "")"
        return proxyUrl.user == nil || proxyUrl.user == "UNUSED_USER" || notMasked
    }
}
