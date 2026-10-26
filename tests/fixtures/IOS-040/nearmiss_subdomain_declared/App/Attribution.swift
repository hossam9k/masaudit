// Near miss: a subdomain of a declared tracking domain, a declared host, a policy link, and a comment-only mention.
import Foundation

enum Attribution {
    static let conversions = URL(string: "https://inapps.appsflyersdk.com/api/v6.13/iosevent")!
    static let events = URL(string: "https://api-eu.mixpanel.com/track")!
    static let policy = URL(string: "https://www.branch.io/policies/privacy-policy/")!
    // Deep links used to resolve through "https://api2.branch.io/v1/open" before the SDK was removed.
}
