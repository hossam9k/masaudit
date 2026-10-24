import Foundation

struct WidgetAPI {
    func token() -> String? {
        let defaults = UserDefaults(suiteName: "group.com.example.app")
        return defaults?.string(forKey: "widget_auth_token")
    }
}
