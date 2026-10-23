import Foundation

func loadOrder(from data: Data) -> Any? {
    return NSKeyedUnarchiver.unarchiveObject(with: data)
}

func loadCart(from data: Data) throws -> Any? {
    return try NSKeyedUnarchiver.unarchiveTopLevelObjectWithData(data)
}
