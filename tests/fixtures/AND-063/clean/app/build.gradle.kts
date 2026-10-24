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
    debug {
        externalNativeBuild {
            cmake {
                arguments += "-DCMAKE_BUILD_TYPE=Debug"
            }
        }
        packaging { jniLibs { keepDebugSymbols += "**/*.so" } }
    }
    release {
        ndk {
            debugSymbolLevel = "FULL"
        }
    }
}
    }
