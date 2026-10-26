// Near miss: the endpoint connection uses TLS, a Bonjour service on the LAN uses plain TCP, and a stream task goes to 443.
import Foundation
import Network

final class ChatClient {
    func open() -> NWConnection {
        let connection = NWConnection(to: .hostPort(host: "chat.example.com", port: 5223), using: .tls)
        connection.start(queue: .global())
        return connection
    }

    func printer() -> NWConnection {
        NWConnection(to: .service(name: "Office Printer", type: "_ipp._tcp", domain: "local.", interface: nil),
                     using: .tcp)
    }

    func feed(session: URLSession) -> URLSessionStreamTask {
        let task = session.streamTask(withHostName: "feed.example.com", port: 443)
        task.startSecureConnection()
        return task
    }
}
