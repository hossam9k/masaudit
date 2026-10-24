android {
    signingConfigs {
        create("qa") {
            storeFile = file("qa.keystore")
            storePassword = System.getenv("KS_PASS")
        }
    }
}
