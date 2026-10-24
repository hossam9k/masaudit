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
    debug { buildConfigField("boolean", "VERBOSE_LOGS", "true") }
    release { buildConfigField("boolean", "VERBOSE_LOGS", "false") }
}
    }
