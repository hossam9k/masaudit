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
        enableV2Signing = false
        enableV3Signing = true
    }
    getByName("debug") {
        enableV2Signing = false
    }
}
    }
