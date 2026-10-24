import AdSupport
import AppTrackingTransparency

func adID(_ done: @escaping (UUID?) -> Void) {
    ATTrackingManager.requestTrackingAuthorization { status in
        done(status == .authorized ? ASIdentifierManager.shared().advertisingIdentifier : nil)
    }
}
