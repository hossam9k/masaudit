import UIKit

func copyPassword(_ password: String) {
    UIPasteboard.general.string = password
}
