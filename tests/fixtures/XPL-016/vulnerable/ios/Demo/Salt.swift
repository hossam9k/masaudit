let salt = "demo-app-salt"
let status = CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), password, password.count, salt, salt.count, CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), 600000, &derived, derived.count)
