plugins {
    id("com.android.application")
}

android {
    defaultConfig {
        targetSdk = rootProject.extra["target"] as Int
    }
}
