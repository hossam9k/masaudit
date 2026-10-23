plugins {
    id("com.android.application")
}

android {
    buildTypes {
        debug {
            isDebuggable = true
        }
        release {
            // isDebuggable = true
            isDebuggable = false
            buildConfigField("boolean", "debuggable", "true")
        }
    }
}
