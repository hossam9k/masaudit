import Parse
import UIKit

final class Signup {
    func signUp(name: String, password: String) {
        let user = PFObject(className: "Person")
        user["name"] = name
        print("user saved: \(user.description)")
        user["password"] = password
        user.saveInBackground()
    }

    func profile(name: String) {
        let user = PFObject(className: "Person")
        user["name"] = name
        print("profile: \(user)")
    }
}
