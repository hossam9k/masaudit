// The sign-in page opens in Safari and the code comes back through the OS to a custom scheme.
import UIKit

enum OAuth {
    static let redirectURI = "acmebank://oauth/callback"

    static func start() {
        let url = URL(string: "https://id.example.com/authorize?client_id=app&redirect_uri=\(redirectURI)")!
        UIApplication.shared.open(url)
    }
}
