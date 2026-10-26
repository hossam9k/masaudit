// A second, unconditional IDFA read in the analytics layer.
import AdSupport

struct Analytics {
    var deviceID: String { ASIdentifierManager.shared().advertisingIdentifier.uuidString }
}
