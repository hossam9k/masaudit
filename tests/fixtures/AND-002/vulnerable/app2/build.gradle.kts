plugins {
    id("com.android.application")
}

android {
    buildTypes {
        getByName("release") {
            isDebuggable = true
        }
    }
}
