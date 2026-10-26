// Only api-eu.mixpanel.com is declared; the app also sends events to api.mixpanel.com.
import Foundation

enum Analytics {
    static let euEvents = URL(string: "https://api-eu.mixpanel.com/track")!
    static let usEvents = URL(string: "https://api.mixpanel.com/track")!
}
