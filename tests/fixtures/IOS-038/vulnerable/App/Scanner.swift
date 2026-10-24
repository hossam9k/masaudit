import AVFoundation
import CoreLocation

final class Scanner {
    let location = CLLocationManager()
    func start() {
        AVCaptureDevice.requestAccess(for: .video) { _ in }
        location.requestWhenInUseAuthorization()
    }
}
