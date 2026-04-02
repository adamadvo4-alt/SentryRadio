android {
    signingConfigs {
        release {
            keyAlias = "androiddebugkey"
            keyPassword = "android"
            storePassword = "android"
            storeFile = file("~/.android/debug.keystore")
        }
    }
    buildTypes {
        release {
            signingConfig signingConfigs.release
        }
    }
}