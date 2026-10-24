import UIKit

final class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?
    func sceneWillResignActive(_ scene: UIScene) {
        let cover = UIVisualEffectView(effect: UIBlurEffect(style: .systemThickMaterial))
        cover.frame = window?.bounds ?? .zero
        window?.addSubview(cover)
    }
}
