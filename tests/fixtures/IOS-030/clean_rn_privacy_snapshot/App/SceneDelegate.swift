import UIKit

final class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    func sceneWillResignActive(_ scene: UIScene) {
        saveState()
    }
    func saveState() {}
}
