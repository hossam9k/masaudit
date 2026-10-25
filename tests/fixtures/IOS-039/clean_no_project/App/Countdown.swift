import UIKit

struct Countdown {
    static func start(seconds: Int, done: @escaping () -> Void) {
        DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(seconds)) { done() }
    }
}
