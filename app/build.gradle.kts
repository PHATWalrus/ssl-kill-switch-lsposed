plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "com.horizon.sslkillswitch"
    compileSdk = 37
    buildToolsVersion = "37.0.0"

    defaultConfig {
        applicationId = "com.horizon.sslkillswitch"
        minSdk = 26
        targetSdk = 37
        versionCode = 1
        versionName = "1.0.0"

        externalNativeBuild {
            cmake {
                cppFlags("-std=c++17", "-fvisibility=hidden")
                abiFilters("arm64-v8a", "armeabi-v7a")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs["debug"]
        }
        debug {
            isMinifyEnabled = false
            isShrinkResources = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/jni/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    buildFeatures {
        viewBinding = true
        buildConfig = true
    }

    packaging {
        resources {
            excludes += setOf(
                "META-INF/LICENSE",
                "META-INF/LICENSE.txt",
                "META-INF/NOTICE",
                "META-INF/NOTICE.txt",
                "META-INF/AL2.0",
                "META-INF/LGPL2.1",
                "META-INF/*.kotlin_module",
                "META-INF/INDEX.LIST",
                "kotlin-tooling-metadata.json",
                "kotlin/**",
                "META-INF/services/*",
                "META-INF/com/android/build/gradle/*",
                "META-INF/version-control-info.textproto",
            )
        }
    }

    lint {
        abortOnError = true
        checkReleaseBuilds = false
    }
}

kotlin { jvmToolchain(21) }

dependencies {
    compileOnly("de.robv.android.xposed:api:82")
    implementation(libs.appcompat)
    implementation(libs.material)
    implementation(libs.recyclerview)
}
