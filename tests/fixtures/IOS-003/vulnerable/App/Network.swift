import Foundation

func makeSession() -> URLSession {
    let configuration = URLSessionConfiguration.default
    configuration.tlsMinimumSupportedProtocolVersion = .TLSv11
    return URLSession(configuration: configuration)
}
