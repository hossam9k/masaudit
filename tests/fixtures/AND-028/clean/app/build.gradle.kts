plugins {
    id("com.android.application")
}

android {
    defaultConfig {
        // targetSdk = 30
        targetSdk = 36
    }
    lint {
        targetSdk = 30
    }
    testOptions.targetSdk = 30
}
