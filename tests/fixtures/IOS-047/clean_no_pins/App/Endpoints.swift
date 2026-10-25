import Foundation

// Near miss: the app doesn't use NSPinnedDomains at all (IOS-007 covers missing pinning).
func fetchPayments() {
    let url = URL(string: "https://payments.example.net/v1/transfers")!
    URLSession.shared.dataTask(with: url) { _, _, _ in }.resume()
}
