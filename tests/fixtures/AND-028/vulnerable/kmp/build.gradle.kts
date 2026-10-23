plugins {
    id("com.android.application")
}

android {
    defaultConfig {
        targetSdk = libs.versions.targetSdk.get().toInt()
    }
}
