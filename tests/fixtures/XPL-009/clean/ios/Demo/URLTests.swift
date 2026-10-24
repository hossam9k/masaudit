import XCTest
final class URLTests: XCTestCase {
    func testSanitized() { XCTAssertEqual(URL(string: "http://vendor.com")?.sanitized, nil) }
}
