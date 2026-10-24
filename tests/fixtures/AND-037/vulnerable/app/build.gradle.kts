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
    implementation("com.facebook.stetho:stetho:1.6.0")
    releaseImplementation(libs.chucker)
    implementation(libs.leakcanary.android)
}
