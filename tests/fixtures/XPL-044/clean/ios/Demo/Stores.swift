import Foundation

final class Stores {
    func savePlist(username: String, theme: String, path: String) {
        let data = NSMutableDictionary()
        data.setValue(username, forKey: "username")
        data.setValue(theme, forKey: "theme")
        data.write(toFile: path, atomically: true)
    }

    func saveSessionCookie(site: URL, sessionName: String) {
        let properties: [HTTPCookiePropertyKey: Any] = [.domain: site.host ?? "", .path: "/",
                                                        .name: "locale", .value: sessionName]
        guard let cookie = HTTPCookie(properties: properties) else { return }
        HTTPCookieStorage.shared.setCookie(cookie)
    }
}
