    plugins {
        id("com.android.application")
    }

    android {
        namespace = "com.example.bank"
        defaultConfig {
            applicationId = "com.example.bank"
            minSdk = 26
            targetSdk = 35
        }
        signingConfigs {
    create("release") {
        storeFile = file("release.jks")
        enableV1Signing = true
        enableV2Signing = false
    }
}
    }
