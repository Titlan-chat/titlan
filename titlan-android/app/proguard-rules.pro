# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: 2026 Oculux Technologies LLC
#
# Inert while isMinifyEnabled = false (app/build.gradle.kts); pinned by
# check-invariants family 18d so a future minify flip cannot strip the
# JNI-reached verifier component (5d-3).
-keep, includedescriptorclasses class org.rustls.platformverifier.** { *; }
