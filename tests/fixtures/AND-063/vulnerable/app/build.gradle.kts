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
        packaging {
    jniLibs {
        keepDebugSymbols += "**/*.so"
    }
}
buildTypes {
    release {
        externalNativeBuild {
            cmake {
                arguments += "-DCMAKE_BUILD_TYPE=Debug"
            }
        }
    }
}
    }
