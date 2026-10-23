plugins {
    id("com.android.application")
}

android {
    buildTypes {
        release {
            optimization {
                enable = false
            }
        }
    }
}
