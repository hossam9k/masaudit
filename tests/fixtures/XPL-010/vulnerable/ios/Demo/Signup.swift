import Parse
import UIKit

final class Signup {
    func signUp(name: String, password: String) {
        let user = PFObject(className: "Person")
        user["name"] = name
        user["password"] = password
        print("user saved: \(user.description)")
        user.saveInBackground()
    }
}
