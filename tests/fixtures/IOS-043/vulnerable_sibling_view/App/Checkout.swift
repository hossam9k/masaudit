// The search box turns autocorrection off; the card number field in another view doesn't.
import SwiftUI

struct SearchBar: View {
    @State private var query = ""
    var body: some View {
        TextField("Search", text: $query).autocorrectionDisabled()
    }
}

struct PaymentForm: View {
    @State private var cardNumber = ""
    var body: some View {
        TextField("Card number", text: $cardNumber)
    }
}
