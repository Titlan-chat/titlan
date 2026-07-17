// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! Thin CLI wrapper so the Gradle build can run `uniffi-bindgen generate
//! --library` against the compiled `libtezca_core.so` (A3: bindings are
//! generated at build time, never committed).

fn main() {
    uniffi::uniffi_bindgen_main()
}
