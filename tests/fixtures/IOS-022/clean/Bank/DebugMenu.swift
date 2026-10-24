import UIKit
#if DEBUG
import FLEX
#endif
#if canImport(Wormholy)
import Wormholy
#endif

func showDebugMenu() {
#if DEBUG
    FLEXManager.shared.showExplorer()
#endif
}
