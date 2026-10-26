// The Swift spellings of the session's TLS floor and ceiling, set to TLS 1.2 and 1.3.
import Foundation

func legacySession() -> URLSession {
    let config = URLSessionConfiguration.default
    config.tlsMinimumSupportedProtocol = .tlsProtocol12
    config.tlsMaximumSupportedProtocolVersion = .TLSv13
    return URLSession(configuration: config)
}
