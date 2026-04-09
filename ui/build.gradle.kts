@file:Suppress("UnstableApiUsage")

import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import java.util.Properties

val pkg: String = providers.gradleProperty("wireguardPackageName").get()
val defaultOtaReleaseMetaUrl = "https://github.com/releases/latest/download/ota-release.json"
val defaultOtaDebugMetaUrl = defaultOtaReleaseMetaUrl
val defaultDonationsUrl = "https://github.com/Yasich217/wireguard-turn-android#donations--%D0%BF%D0%BE%D0%B4%D0%B4%D0%B5%D1%80%D0%B6%D0%B0%D1%82%D1%8C-%D1%80%D0%B0%D0%B7%D1%80%D0%B0%D0%B1%D0%BE%D1%82%D0%BA%D1%83"
fun pickValue(envKey: String, gradleKey: String, fallback: String): String {
    val envValue = System.getenv(envKey)?.trim()
    if (!envValue.isNullOrEmpty()) return envValue
    val gradleValue = providers.gradleProperty(gradleKey).orNull?.trim()
    if (!gradleValue.isNullOrEmpty()) return gradleValue
    return fallback
}
val otaReleaseMetaUrl: String = pickValue("OTA_RELEASE_META_URL", "otaReleaseMetaUrl", defaultOtaReleaseMetaUrl)
val otaDebugMetaUrl: String = pickValue("OTA_DEBUG_META_URL", "otaDebugMetaUrl", defaultOtaDebugMetaUrl)
val donationsUrl: String = pickValue("DONATIONS_URL", "donationsUrl", defaultDonationsUrl)
val otaPinnedCaEnabled: Boolean = pickValue("OTA_PINNED_CA_ENABLED", "otaPinnedCaEnabled", "false").toBoolean()
val otaPinnedCaResName: String = pickValue("OTA_PINNED_CA_RES", "otaPinnedCaResName", "ota_root_ca")

fun asBuildConfigString(value: String): String =
    "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

val signingPropsFile = rootProject.file("signing.properties")
val signingProps = Properties().apply {
    if (signingPropsFile.isFile) {
        signingPropsFile.inputStream().use { load(it) }
    }
}
val hasLocalSigning = signingProps.isNotEmpty()

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.kapt)
}

android {
    compileSdk = 36
    buildFeatures {
        buildConfig = true
        dataBinding = true
        viewBinding = true
    }
    namespace = "com.wireguard.android"
    defaultConfig {
        applicationId = pkg
        minSdk = 24
        targetSdk = 36
        versionCode = providers.gradleProperty("wireguardVersionCode").get().toInt()
        versionName = providers.gradleProperty("wireguardVersionName").get()
        buildConfigField("int", "MIN_SDK_VERSION", minSdk.toString())
        buildConfigField("String", "OTA_RELEASE_META_URL", asBuildConfigString(otaReleaseMetaUrl))
        buildConfigField("String", "OTA_DEBUG_META_URL", asBuildConfigString(otaDebugMetaUrl))
        buildConfigField("String", "DONATIONS_URL", asBuildConfigString(donationsUrl))
        buildConfigField("boolean", "OTA_PINNED_CA_ENABLED", otaPinnedCaEnabled.toString())
        buildConfigField("String", "OTA_PINNED_CA_RES", asBuildConfigString(otaPinnedCaResName))
        ndk {
            abiFilters.addAll(listOf("armeabi-v7a", "arm64-v8a"))
        }
    }
    splits {
        abi {
            isEnable = true
            reset()
            include("armeabi-v7a", "arm64-v8a")
            isUniversalApk = true
        }
    }
    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
        isCoreLibraryDesugaringEnabled = true
    }
    if (hasLocalSigning) {
        signingConfigs {
            create("localRelease") {
                val storePath = signingProps.getProperty("storeFile")
                require(!storePath.isNullOrBlank()) { "signing.properties: storeFile is required" }
                storeFile = rootProject.file(storePath)
                storePassword = signingProps.getProperty("storePassword")
                keyAlias = signingProps.getProperty("keyAlias")
                keyPassword = signingProps.getProperty("keyPassword")
            }
        }
    }
    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            if (hasLocalSigning) {
                signingConfig = signingConfigs.getByName("localRelease")
            } else {
                signingConfig = signingConfigs.getByName("debug")
            }
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-android-optimize.txt")
            packaging {
                resources {
                    excludes += "DebugProbesKt.bin"
                    excludes += "kotlin-tooling-metadata.json"
                    excludes += "META-INF/*.version"
                }
            }
        }
        debug {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
            if (hasLocalSigning) {
                signingConfig = signingConfigs.getByName("localRelease")
            }
        }
        create("googleplay") {
            initWith(getByName("release"))
            matchingFallbacks += "release"
        }
    }
    androidResources {
        generateLocaleConfig = true
    }
    lint {
        disable += "LongLogTag"
        warning += "MissingTranslation"
        warning += "ImpliedQuantity"
    }
}

dependencies {
    implementation(project(":tunnel"))
    implementation(libs.androidx.activity.ktx)
    implementation(libs.androidx.annotation)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.constraintlayout)
    implementation(libs.androidx.coordinatorlayout)
    implementation(libs.androidx.biometric)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.webkit)
    implementation(libs.androidx.fragment.ktx)
    implementation(libs.androidx.preference.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.datastore.preferences)
    implementation(libs.google.material)
    implementation(libs.zxing.android.embedded)
    implementation(libs.kotlinx.coroutines.android)
    coreLibraryDesugaring(libs.desugarJdkLibs)
}

tasks.withType<JavaCompile>().configureEach {
    options.compilerArgs.add("-Xlint:unchecked")
    options.isDeprecation = true
}

tasks.withType<KotlinCompile>().configureEach {
    compilerOptions.jvmTarget = JvmTarget.JVM_17
}
