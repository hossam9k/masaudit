// Near miss: async ATT request before the read; the purpose string comes from INFOPLIST_KEY_ (generated Info.plist).
import AdSupport
import AppTrackingTransparency

@MainActor
func attributionID() async -> UUID? {
    guard await ATTrackingManager.requestTrackingAuthorization() == .authorized else { return nil }
    return ASIdentifierManager.shared().advertisingIdentifier
}
