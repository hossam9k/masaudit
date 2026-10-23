plugins {
    id("com.android.application")
    kotlin("android")
}

android {
    namespace = "com.acme.wallet"
    compileSdk = 36
    defaultConfig {
        applicationId = "com.acme.wallet"
        minSdk = 23
        targetSdk = 34
    }
    buildTypes {
        release {
            isMinifyEnabled = false
            isDebuggable = true
        }
    }
}

dependencies {
    implementation("androidx.security:security-crypto:1.1.0")
    implementation("com.squareup.okhttp3:logging-interceptor:4.12.0")
    implementation("com.stripe:stripe-android:21.0.0")
}
