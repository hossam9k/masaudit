import Foundation

enum SharedStore {
    static func save(widgetSnapshot: Data) throws {
        guard let group = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: "group.com.example") else { return }
        try widgetSnapshot.write(to: group.appendingPathComponent("timeline.json"))
    }

    static func session() -> URLSession {
        let config = URLSessionConfiguration.background(withIdentifier: "bg")
        config.sharedContainerIdentifier = "group.com.example"
        _ = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: "group.com.example")
        return URLSession(configuration: config)
    }
}
