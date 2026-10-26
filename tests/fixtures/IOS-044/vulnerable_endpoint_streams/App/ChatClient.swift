// Vulnerable: NWConnection built from an endpoint with TLS explicitly disabled, and a Foundation stream pair to port 80.
import Foundation
import Network

final class ChatClient {
    func open() -> NWConnection {
        let connection = NWConnection(to: .hostPort(host: "chat.example.com", port: 5222),
                                      using: NWParameters(tls: nil))
        connection.start(queue: .global())
        return connection
    }

    func openFeed() {
        var input: InputStream?
        var output: OutputStream?
        Stream.getStreamsToHost(withName: "feed.example.com", port: 80, inputStream: &input, outputStream: &output)
        input?.open()
        output?.open()
    }
}
