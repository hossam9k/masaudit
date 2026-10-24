import WebKit

func makeConfiguration() -> WKWebViewConfiguration {
    let configuration = WKWebViewConfiguration()
    configuration.preferences.setValue(false, forKey: "allowFileAccessFromFileURLs")
    // configuration.preferences.setValue(true, forKey: "allowFileAccessFromFileURLs")
#if DEBUG
    configuration.setValue(true, forKey: "allowUniversalAccessFromFileURLs")
#endif
    return configuration
}
