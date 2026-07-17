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

// Pinned NDK (4b-1 green): single-sourced here for both AGP's ndkVersion and
// cargo-ndk's toolchain discovery, so the reproducible-build pipeline and
// local builds compile the Rust core with the identical toolchain.
val pinnedNdkVersion = "28.2.13676358"
val repoRoot: File = rootDir.parentFile
val rustJniLibsDir = layout.buildDirectory.dir("rustJniLibs")
val uniffiKotlinDir = layout.buildDirectory.dir("generated/uniffi/kotlin")

android {
    // Internal code namespace, intentionally decoupled from the applicationId
    // so the published id can change (work order §10.4) without touching source.
    namespace = "app.titlan"
    compileSdk = 36
    ndkVersion = pinnedNdkVersion

    defaultConfig {
        applicationId = titlanApplicationId
        // GrapheneOS-supported devices all run Android 13+; revisit only if a
        // concrete target device requires lower (not a locked decision).
        minSdk = 33
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
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

    sourceSets {
        getByName("main") {
            kotlin.srcDir(uniffiKotlinDir)
            jniLibs.srcDir(rustJniLibsDir)
        }
    }
}

// --- tezca-core native build + UniFFI bindings (A3) -------------------------
// The Rust core is cross-compiled per ABI with cargo-ndk and the Kotlin
// bindings are generated from the compiled library at build time — generated
// sources and .so files live under build/, NEVER committed.

val cargoNdkBuild by tasks.registering(Exec::class) {
    group = "build"
    description = "Cross-compiles tezca-core for Android ABIs via cargo-ndk"
    workingDir = repoRoot
    environment(
        "ANDROID_NDK_HOME",
        File(android.sdkDirectory, "ndk/$pinnedNdkVersion").absolutePath,
    )
    // The workspace release profile strips .symtab, which uniffi-bindgen's
    // library mode needs for metadata extraction. Build these .so unstripped
    // — AGP strips packaged jniLibs itself, so the APK is unaffected.
    environment("CARGO_PROFILE_RELEASE_STRIP", "none")
    commandLine(
        "cargo", "ndk",
        "-t", "arm64-v8a",
        "-t", "x86_64",
        "-o", rustJniLibsDir.get().asFile.absolutePath,
        "build", "--release", "-p", "tezca-core", "--locked",
    )
}

val generateUniffiBindings by tasks.registering(Exec::class) {
    group = "build"
    description = "Generates Kotlin bindings from libtezca_core.so (never committed)"
    dependsOn(cargoNdkBuild)
    workingDir = repoRoot
    commandLine(
        "cargo", "run", "-p", "uniffi-bindgen", "--locked", "--",
        "generate",
        "--library",
        File(repoRoot, "target/x86_64-linux-android/release/libtezca_core.so").absolutePath,
        "--language", "kotlin",
        "--out-dir", uniffiKotlinDir.get().asFile.absolutePath,
    )
}

tasks.named("preBuild") {
    dependsOn(generateUniffiBindings)
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
    // JNA (AAR packaging): required at runtime by the UniFFI-generated
    // Kotlin bindings to load and call libtezca_core.so.
    implementation(variantOf(libs.jna) { artifactType("aar") })
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.test.core)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
}
