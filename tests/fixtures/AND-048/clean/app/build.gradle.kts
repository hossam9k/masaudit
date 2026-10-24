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

}

dependencies {
    implementation("com.google.android.play:integrity:1.4.0")
}
