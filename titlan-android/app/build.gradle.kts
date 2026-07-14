// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.cyclonedx)
}

// Work order §6 (Phase 1): the applicationId exists in exactly ONE place —
// TITLAN_APPLICATION_ID in gradle.properties. Never write the package string
// here or anywhere else; scripts/check-invariants.sh enforces this in CI.
val titlanApplicationId: String = providers.gradleProperty("TITLAN_APPLICATION_ID").get()

android {
    // Internal code namespace, intentionally decoupled from the applicationId
    // so the published id can change (work order §10.4) without touching source.
    namespace = "app.titlan"
    compileSdk = 36

    defaultConfig {
        applicationId = titlanApplicationId
        // GrapheneOS-supported devices all run Android 13+; revisit only if a
        // concrete target device requires lower (not a locked decision).
        minSdk = 33
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            // No signingConfig on purpose: CI produces UNSIGNED release APKs.
            // Signing keys are external to the repo and to CI — see README
            // "Release signing".
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    lint {
        abortOnError = true
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

// INV-7: lockfile committed (gradle.lockfile). Regenerate deliberately with:
//   ./gradlew :app:assembleDebug :app:assembleRelease :app:lintDebug :app:testDebugUnitTest --write-locks
dependencyLocking {
    lockAllConfigurations()
}

// SBOM for what ships in the APK (work order §6 Phase 1 / §7).
tasks.cyclonedxDirectBom {
    includeConfigs = listOf("releaseRuntimeClasspath")
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.compose.material3)
    testImplementation(libs.junit)
}
