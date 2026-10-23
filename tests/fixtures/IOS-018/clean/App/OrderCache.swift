import Foundation

// DON'T: NSKeyedUnarchiver.unarchiveObject(with: data) builds whatever the archive names.
func loadOrder(from data: Data) throws -> LegacyOrder? {
    return try NSKeyedUnarchiver.unarchivedObject(ofClass: LegacyOrder.self, from: data)
}

func loadCart(from data: Data) throws -> Cart {
    try JSONDecoder().decode(Cart.self, from: data)
}
