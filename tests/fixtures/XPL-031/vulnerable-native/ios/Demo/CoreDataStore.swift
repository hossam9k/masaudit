import CoreData
import UIKit

final class CoreDataStore {
    func save(email: String, password: String, context: NSManagedObjectContext) throws {
        let newUser = NSEntityDescription.insertNewObject(forEntityName: "User", into: context) as? User
        newUser?.email = email
        newUser?.password = password
        try context.save()
    }
}
