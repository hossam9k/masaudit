plugins {
    id("com.android.library")
}

android {
    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
}
