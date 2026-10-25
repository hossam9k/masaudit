import Foundation
import YapDatabase

final class Stores {
    func savePlist(username: String, password: String, path: String) {
        let data = NSMutableDictionary()
        data.setValue(username, forKey: "username")
        data.setValue(password, forKey: "password")
        data.write(toFile: path, atomically: true)
    }

    func saveYap(connection: YapDatabaseConnection, password: String) {
        connection.readWrite { transaction in
            transaction.setObject(password, forKey: "Password", inCollection: "Accounts")
        }
    }

    func saveCookie(site: URL, password: String) {
        let passwordProperties: [HTTPCookiePropertyKey: Any] = [.domain: site.host ?? "", .path: "/",
                                                                .name: "password", .value: password]
        guard let passwordCookie = HTTPCookie(properties: passwordProperties) else { return }
        HTTPCookieStorage.shared.setCookie(passwordCookie)
    }
}
