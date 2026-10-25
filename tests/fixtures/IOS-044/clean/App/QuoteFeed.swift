import Foundation
import Network

// Near misses: TLS parameters, plain TCP only to a device on the local network, TCP chosen at run
// time next to TLS, and a socket to the HTTPS port.
final class QuoteFeed {
    func secure() -> NWConnection {
        let host = NWEndpoint.Host("quotes.example.com")
        return NWConnection(host: host, port: .https, using: NWParameters(tls: NWProtocolTLS.Options()))
    }

    func printer() -> NWConnection {
        NWConnection(host: NWEndpoint.Host("192.168.1.20"), port: 9100, using: .tcp)
    }

    func proxy(host: String, port: UInt16, plain: Bool) -> NWConnection {
        let params: NWParameters
        if plain {
            params = .tcp
        } else {
            params = .tls
        }
        return NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(integerLiteral: port), using: params)
    }
}

func openSecureSocket(host: String) {
    var hints = addrinfo()
    var info: UnsafeMutablePointer<addrinfo>?
    _ = getaddrinfo(host, "443", &hints, &info)
}
