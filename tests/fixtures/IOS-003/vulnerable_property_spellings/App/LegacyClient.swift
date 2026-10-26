// The Swift spellings of the session's TLS floor and ceiling, set below TLS 1.2.
import Foundation

func legacySession() -> URLSession {
    let config = URLSessionConfiguration.default
    config.tlsMinimumSupportedProtocol = .tlsProtocol1
    config.tlsMaximumSupportedProtocolVersion = .TLSv11
    return URLSession(configuration: config)
}
