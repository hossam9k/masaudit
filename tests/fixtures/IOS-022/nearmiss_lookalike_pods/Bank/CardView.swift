// Near miss: FlexLayout is a layout engine, not the FLEX debugger.
import FlexLayout
import PinLayout
import UIKit

final class CardView: UIView {
    let root = UIView()
    override func layoutSubviews() {
        super.layoutSubviews()
        root.pin.all()
        root.flex.layout()
    }
}
