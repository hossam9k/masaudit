plugins {
    id("com.android.application")
}

android {
    buildTypes {
        debug {
            isMinifyEnabled = false
        }
        release {
            // isMinifyEnabled = false
            isMinifyEnabled = true
            isShrinkResources = true
        }
    }
}
