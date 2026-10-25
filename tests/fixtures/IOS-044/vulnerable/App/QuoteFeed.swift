import Foundation
import Network

final class QuoteFeed {
    func connect() -> NWConnection {
        let host = NWEndpoint.Host("quotes.example.com")
        let port = NWEndpoint.Port(integerLiteral: 80)
        let connection = NWConnection(host: host, port: port, using: .tcp)
        connection.start(queue: .main)
        return connection
    }
}
