import Foundation
import RealmSwift

class Bookmark: Object {
    @Persisted var title: String
    @Persisted var token: String
}
