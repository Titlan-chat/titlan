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

// SOURCE_DATE_EPOCH for the Rust cross-build: SQLCipher's vendored OpenSSL
// bakes an OPENSSL_BUILT_ON banner into libtezca_core.so; pinning this to
// the commit time makes the .so reproducible. An externally provided
// SOURCE_DATE_EPOCH (e.g. scripts/repro-build.sh, whose build tree has no
// .git) takes precedence; falls back to "0" when git is unavailable so
// configuration never breaks.
val sourceDateEpoch: String = System.getenv("SOURCE_DATE_EPOCH")
    ?: try {
        val proc = ProcessBuilder("git", "-C", repoRoot.absolutePath, "log", "-1", "--format=%ct")
            .redirectErrorStream(true)
            .start()
        val out = proc.inputStream.bufferedReader().readText().trim()
        if (proc.waitFor() == 0 && out.isNotEmpty()) out else "0"
    } catch (_: Exception) {
        "0"
    }
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
        // Custom runner (androidTest source set): exports the CI relay TLS pin
        // from instrumentation args to the process env before app creation.
        testInstrumentationRunner = "app.titlan.TitlanTestRunner"

        // Default relay for THIS device's own inboxes (INV-5: per-conversation
        // relay still overrides; this is only the bootstrap/pairing default).
        // RFC 2606 placeholder for release — a real onboarding relay picker is
        // post-MVP. Debug overrides it to the CI test relay (below).
        buildConfigField("String", "RELAY_URL", "\"wss://relay.invalid\"")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            // No signingConfig on purpose: CI produces UNSIGNED release APKs.
            // Signing keys are external to the repo and to CI — see README
            // "Release signing".
        }
        debug {
            // The instrumented suites reach the CI test relay over the emulator
            // host loopback (10.0.2.2). The relay serves rcgen TLS; trust is a
            // debug-only test anchor in the Rust rustls client (feature-gated,
            // absent from release .so — check-invariants.sh), NOT the Android
            // TLS stack: the core's own sockets never consult the platform
            // network security config. Port set by the ci.yml relay launch.
            //
            // Device checklist (f) (maintainer-ratified F3):
            // -PtitlanDebugRelayUrl=wss://<LAN-host>:<port> points the DEBUG
            // build at a tezca-relay on the build host's LAN address for a
            // physical Pixel; unset, the emulator host-loopback default
            // stands. Debug-only by construction — the release buildType and
            // defaultConfig never read the property
            // (scripts/check-invariants.sh §7).
            buildConfigField(
                "String",
                "RELAY_URL",
                "\"${providers.gradleProperty("titlanDebugRelayUrl").getOrElse("wss://10.0.2.2:8443")}\"",
            )
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
        }
        // Per-variant .so: the debug core carries the feature-gated CI relay
        // trust anchor; the release core is built WITHOUT it (maintainer-
        // ratified 4b-2; asserted by scripts/check-invariants.sh).
        getByName("debug") {
            jniLibs.srcDir(rustJniLibsDir.map { it.dir("debug") })
        }
        getByName("release") {
            jniLibs.srcDir(rustJniLibsDir.map { it.dir("release") })
        }
    }
}

// --- tezca-core native build + UniFFI bindings (A3) -------------------------
// The Rust core is cross-compiled per ABI with cargo-ndk and the Kotlin
// bindings are generated from the compiled library at build time — generated
// sources and .so files live under build/, NEVER committed.

// Two cargo-ndk builds, one per variant: debug enables the feature-gated CI
// relay trust anchor; release builds the identical crate WITHOUT it, so the
// shipped .so contains no anchor code path (check-invariants.sh asserts the
// split stays exactly here). Both share the cargo target dir — flipping
// features between variants recompiles only tezca-core itself.
fun Exec.cargoNdkCommon() {
    group = "build"
    workingDir = repoRoot
    environment(
        "ANDROID_NDK_HOME",
        File(android.sdkDirectory, "ndk/$pinnedNdkVersion").absolutePath,
    )
    // The workspace release profile strips .symtab, which uniffi-bindgen's
    // library mode needs for metadata extraction. Build these .so unstripped
    // — AGP strips packaged jniLibs itself, so the APK is unaffected.
    environment("CARGO_PROFILE_RELEASE_STRIP", "none")
    environment("SOURCE_DATE_EPOCH", sourceDateEpoch)
}

val cargoNdkBuildDebug by tasks.registering(Exec::class) {
    cargoNdkCommon()
    description = "Cross-compiles tezca-core (with test-relay-anchor) for the debug APK"
    commandLine(
        "cargo", "ndk",
        "-t", "arm64-v8a",
        "-t", "x86_64",
        "-o", rustJniLibsDir.get().dir("debug").asFile.absolutePath,
        "build", "--release", "-p", "tezca-core", "--locked",
        "--features", "test-relay-anchor",
    )
}

val cargoNdkBuildRelease by tasks.registering(Exec::class) {
    cargoNdkCommon()
    description = "Cross-compiles tezca-core (no test features) for the release APK"
    commandLine(
        "cargo", "ndk",
        "-t", "arm64-v8a",
        "-t", "x86_64",
        "-o", rustJniLibsDir.get().dir("release").asFile.absolutePath,
        "build", "--release", "-p", "tezca-core", "--locked",
    )
}

val generateUniffiBindings by tasks.registering(Exec::class) {
    group = "build"
    description = "Generates Kotlin bindings from libtezca_core.so (never committed)"
    // Bindings come from the debug .so: the FFI surface is identical across
    // variants (the anchor feature touches no FFI), and debug is the variant
    // every fast path (local dev, lint/unit/instrumented CI) already builds.
    dependsOn(cargoNdkBuildDebug)
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

// The release jniLibs merge must see the anchor-free .so. (Debug is already
// covered: preBuild → generateUniffiBindings → cargoNdkBuildDebug.)
tasks.matching { it.name == "mergeReleaseJniLibFolders" || it.name == "mergeReleaseNativeLibs" }
    .configureEach { dependsOn(cargoNdkBuildRelease) }

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
    // Pairing offer QR + camera scanner (design §5).
    implementation(libs.zxing.core)
    implementation(libs.androidx.camera.core)
    implementation(libs.androidx.camera.camera2)
    implementation(libs.androidx.camera.lifecycle)
    implementation(libs.androidx.camera.view)
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.test.core)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
}
