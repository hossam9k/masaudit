// Vulnerable: the attribution host is built with URLComponents, still a literal tracking domain.
import Foundation

func attributionURL(for linkID: String) -> URL? {
    var components = URLComponents()
    components.scheme = "https"
    components.host = "api2.branch.io"
    components.path = "/v1/open"
    components.queryItems = [URLQueryItem(name: "link", value: linkID)]
    return components.url
}
