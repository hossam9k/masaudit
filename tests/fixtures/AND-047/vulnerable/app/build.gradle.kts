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
    release {
        isMinifyEnabled = true
        proguardFiles(
            getDefaultProguardFile("proguard-android.txt"),
            "proguard-rules.pro",
        )
    }
    debug {
        proguardFiles("proguard-debug.pro")
    }
}
defaultConfig {
    testProguardFiles("proguard-test.pro")
}
    }
