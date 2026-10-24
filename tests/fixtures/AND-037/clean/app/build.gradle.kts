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
        flavorDimensions += "store"
productFlavors {
    create("internal") { dimension = "store" }
    create("play") { dimension = "store" }
}
    }

dependencies {
    debugImplementation("com.facebook.stetho:stetho:1.6.0")
    releaseImplementation(libs.chucker.noop)
    debugImplementation(libs.chucker)
    internalImplementation("com.facebook.flipper:flipper:0.250.0")
    releaseImplementation("com.facebook.flipper:flipper-noop:0.250.0")
    implementation("com.squareup.leakcanary:plumber-android:2.14")
    // implementation("com.facebook.stetho:stetho:1.6.0")
}
