// Near miss: debug tool used only from the UI-test bundle.
import netfox
import XCTest

final class NetworkCaptureTests: XCTestCase {
    func testStartsCapture() { NFX.sharedInstance().start() }
}
