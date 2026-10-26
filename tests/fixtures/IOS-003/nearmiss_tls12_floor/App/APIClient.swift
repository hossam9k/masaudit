// Near miss: the floor is TLS 1.2/1.3, and TLS 1.0 only appears in a comment and a log string.
import Foundation

func makeSession() -> URLSession {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.tlsMinimumSupportedProtocolVersion = .TLSv13
    configuration.tlsMaximumSupportedProtocolVersion = .TLSv13
    // was: configuration.tlsMinimumSupportedProtocolVersion = .TLSv10
    print("tlsMinimumSupportedProtocolVersion = .TLSv10 is rejected by policy")
    return URLSession(configuration: configuration)
}
