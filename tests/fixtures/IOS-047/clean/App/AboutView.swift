import SwiftUI

// Near miss: a link the user opens in the browser; this file makes no requests of its own.
struct AboutView: View {
    var body: some View {
        Link("Our blog", destination: URL(string: "https://news.example.org/latest")!)
    }
}
