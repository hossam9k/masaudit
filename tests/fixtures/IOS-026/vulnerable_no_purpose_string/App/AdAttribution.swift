// The ATT prompt is requested, but Info.plist has no NSUserTrackingUsageDescription (the app crashes / is rejected).
import AdSupport
import AppTrackingTransparency

@MainActor
func attributionID() async -> UUID? {
    let status = await ATTrackingManager.requestTrackingAuthorization()
    guard status == .authorized else { return nil }
    return ASIdentifierManager.shared().advertisingIdentifier
}
