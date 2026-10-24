android {
    signingConfigs {
        getByName("debug") {
            storeFile = file("debug.keystore")
            storePassword = "android"
        }
        create("release") {
            storeFile = file("upload.keystore")
            storePassword = System.getenv("UPLOAD_PASS")
        }
    }
}
