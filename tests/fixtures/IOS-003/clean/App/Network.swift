import Foundation

func makeSession() -> URLSession {
    let configuration = URLSessionConfiguration.default
    // Never: configuration.tlsMinimumSupportedProtocolVersion = .TLSv10
    configuration.tlsMinimumSupportedProtocolVersion = .TLSv12
#if DEBUG
    configuration.tlsMinimumSupportedProtocolVersion = .TLSv10   // local test server only
#endif
    return URLSession(configuration: configuration)
}
