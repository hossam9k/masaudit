struct Auth {
    static let clientSecret = ProcessInfo.processInfo.environment["CLIENT_SECRET"] ?? ""
}
