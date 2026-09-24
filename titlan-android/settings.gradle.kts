// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

// rustls-platform-verifier's Android component (5d-3, PV-D1a) is delivered
// inside the locked `rustls-platform-verifier-android` crate as a local Maven
// layout. Resolve that directory through `cargo metadata --locked` so the
// Kotlin half can never drift from the Rust half. Only the `rustls` group is
// served from it.
fun rustlsPlatformVerifierMaven(): String {
    val json = providers.exec {
        workingDir = rootDir.parentFile
        commandLine(
            "cargo", "metadata", "--format-version", "1", "--locked",
            "--filter-platform", "aarch64-linux-android", "--manifest-path", "Cargo.toml",
        )
    }.standardOutput.asText.get()
    @Suppress("UNCHECKED_CAST")
    val packages = (groovy.json.JsonSlurper().parseText(json) as Map<String, Any>)["packages"] as List<Map<String, Any>>
    val manifest = packages.first { it["name"] == "rustls-platform-verifier-android" }["manifest_path"] as String
    return File(File(manifest).parentFile, "maven").path
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        maven {
            url = uri(rustlsPlatformVerifierMaven())
            metadataSources { mavenPom() }
            content { includeGroup("rustls") }
        }
    }
}

rootProject.name = "titlan-android"
include(":app")
