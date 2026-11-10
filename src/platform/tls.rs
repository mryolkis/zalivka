//! Select the host certificate store, with WebPKI fallback on other targets.
use anyhow::Result;
use rustls::{client::danger::ServerCertVerifier, pki_types::CertificateDer};
use std::sync::Arc;

pub(crate) fn public_roots() -> ureq::tls::RootCerts {
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    {
        ureq::tls::RootCerts::PlatformVerifier
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        ureq::tls::RootCerts::WebPki
    }
}

pub(crate) fn verifier(
    extra: Option<CertificateDer<'static>>,
) -> Result<Arc<dyn ServerCertVerifier>> {
    let provider = Arc::new(rustls_rustcrypto::provider());
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    let verifier = Arc::new(if let Some(root) = extra {
        rustls_platform_verifier::Verifier::new_with_extra_roots([root], provider)?
    } else {
        rustls_platform_verifier::Verifier::new(provider)?
    });
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    let verifier = {
        let mut roots = rustls::RootCertStore::empty();
        if let Some(root) = extra {
            roots.add(root)?;
        } else {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
            .build()?
    };
    Ok(verifier)
}
