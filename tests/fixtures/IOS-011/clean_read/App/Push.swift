import Foundation

struct Push {
    func tokens() -> [String?] {
        let defaults = UserDefaults.standard
        return [defaults.string(forKey: "fcm_token"), defaults.string(forKey: "deviceTokenPushNotification"),
                defaults.string(forKey: "lastSyncDate")]
    }
}
