class AndroidApplicationConventionPlugin {
    fun configure() {
        buildTypes { release { isMinifyEnabled = true } }
    }
}
