// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! `tezca-android-trust` — the Android JNI seam that initializes
//! `rustls-platform-verifier` with the application `Context` (5d-3, PV-D2 as
//! amended by ruling R-B).
//!
//! The verifier's Android backend validates certificates through the bundled
//! `org.rustls.platformverifier.CertificateVerifier` Kotlin component, reached
//! via the JVM it captures here. Without this one-time call every connection
//! that carries no per-conversation pin — the production default — panics
//! inside the TLS handshake (`Expect rustls-platform-verifier to be
//! initialized`); that is exactly what v0.1.0-rc.1 shipped (release checklist
//! §8, finding F-C).
//!
//! Why a separate crate: `tezca-core` is `#![forbid(unsafe_code)]` (ledger
//! item 23), and the JNI ABI needs an unmangled symbol, which edition 2024
//! spells `#[unsafe(no_mangle)]` — an unsafe attribute no inner allow can
//! reinstate under a forbid. This crate relaxes that one lint for that one
//! attribute and nothing else; it contains no unsafe block. `tezca-core`
//! links it Android-only with `use tezca_android_trust as _;` so the export
//! lands in `libtezca_core.so`.
//!
//! Called by `app.titlan.core.PlatformTrust.nativeInit(Context)` from
//! `TitlanApp.onCreate`, before any core use. Idempotent: the verifier keeps
//! the runtime in a `OnceCell`. Logs nothing (INV-1): no logger is installed
//! in this process, so the policy's `log::error!` on the impossible error
//! path is inert.

#[cfg(target_os = "android")]
use jni::EnvUnowned;
#[cfg(target_os = "android")]
use jni::errors::{Error as JniError, LogErrorAndDefault};
#[cfg(target_os = "android")]
use jni::objects::{JClass, JObject};
#[cfg(target_os = "android")]
use jni::sys::jboolean;

/// JNI: `app.titlan.core.PlatformTrust.nativeInit(Context): Boolean`.
///
/// Returns `true` once the verifier holds the application context. A `false`
/// (JNI failure while capturing the class loader, or a caught panic) is
/// fatal at startup on the Kotlin side — never a silent non-connecting app.
///
/// The `#[unsafe(no_mangle)]` attribute is the crate's sole reason to exist
/// (see the crate docs). The body performs no unsafe operation: `with_env`
/// attaches the frame and catches unwinds, and the error policy maps every
/// failure to `false`.
#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_titlan_core_PlatformTrust_nativeInit<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    context: JObject<'caller>,
) -> jboolean {
    let outcome = unowned_env.with_env(|env| -> Result<jboolean, JniError> {
        let initialized = rustls_platform_verifier::android::init_with_env(env, context).is_ok();
        Ok(jboolean::from(initialized))
    });
    outcome.resolve::<LogErrorAndDefault>()
}
