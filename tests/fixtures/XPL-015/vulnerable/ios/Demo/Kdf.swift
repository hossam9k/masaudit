let status = CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), password, password.count, salt, salt.count, CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), 100000, &derived, derived.count)
