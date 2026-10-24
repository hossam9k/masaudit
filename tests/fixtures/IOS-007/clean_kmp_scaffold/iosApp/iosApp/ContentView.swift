import SwiftUI
import ComposeApp
struct ContentView: UIViewControllerRepresentable {
    func makeUIViewController(context: Context) -> UIViewController { MainViewControllerKt.MainViewController() }
    func updateUIViewController(_ vc: UIViewController, context: Context) {}
}
