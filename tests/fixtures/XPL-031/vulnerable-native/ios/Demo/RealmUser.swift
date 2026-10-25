import Foundation
import RealmSwift

class RealmUser: Object {
    @objc dynamic var name: String?
    @objc dynamic var password: String?
}

func save(name: String, password: String) {
    let realm = try! Realm()
    let user = RealmUser()
    user.name = name
    user.password = password
    try! realm.write { realm.add(user) }
}
