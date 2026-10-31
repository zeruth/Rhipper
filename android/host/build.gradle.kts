// Rhipper's Android host: the Activity, input and lifecycle glue any Rhipper port can reuse. A port's
// app includes this module by path (see CrystalCore/platform/android/settings.gradle.kts) and
// supplies its own native libraries (runtime32-posix's Runtime32Posix.cmake: lib<name>_boot.so, which
// loads lib<name>.so below 2 GB). The plugin versions come from the including build's root
// build.gradle.kts; AGP 9 compiles the Kotlin itself.
plugins {
    id("com.android.library")
}

android {
    namespace = "dev.rhipper.host"
    compileSdk = 37

    defaultConfig {
        minSdk = 31 // VibratorManager on input devices, WindowInsets.Type, exit-reason traces
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    // FileProvider only: sharing the runtime's logs with another app
    implementation("androidx.core:core:1.16.0")
}
