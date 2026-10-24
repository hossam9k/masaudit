import WebKit

func makeConfiguration() -> WKWebViewConfiguration {
    let configuration = WKWebViewConfiguration()
    configuration.preferences.setValue(true, forKey: "allowFileAccessFromFileURLs")
    configuration.setValue(NSNumber(value: true), forKey: "allowUniversalAccessFromFileURLs")
    return configuration
}
