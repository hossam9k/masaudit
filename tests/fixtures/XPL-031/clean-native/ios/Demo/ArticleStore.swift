import CoreData

final class ArticleStore {
    func save(key: String, context: NSManagedObjectContext) throws {
        let article = Article(context: context)
        article.key = key
        try context.save()
    }
}
