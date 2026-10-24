import AVFoundation
import CoreLocation
import PhotosUI

final class Scanner {
    let location = CLLocationManager()
    func start() {
        AVCaptureDevice.requestAccess(for: .video) { _ in }
        location.requestWhenInUseAuthorization()
        _ = PHPickerViewController(configuration: PHPickerConfiguration())   // no permission needed
    }
}
