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
        buildTypes {
    debug {
        isJniDebuggable = true
        enableAndroidTestCoverage = true
    }
    create("staging") {
        initWith(getByName("debug"))
        isRenderscriptDebuggable = true
    }
    release {
        isMinifyEnabled = true
        isJniDebuggable = false
    }
}
    }
