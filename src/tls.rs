//! TLS trust helpers for the agent's outbound HTTPS clients.
//!
//! By default the blocking `reqwest` clients verify the server certificate
//! against the built-in WebPKI root store. Deployments that terminate the
//! Mayfly server's TLS with a **private / internal CA** (rather than a publicly
//! trusted one) can pin that CA by setting
//! [`Config::tls_ca_path`](crate::config::Config::tls_ca_path); the referenced
//! PEM bundle is added to the client's trust anchors *in addition to* the
//! built-in roots. This keeps full certificate verification enabled — it is the
//! secure alternative to
//! [`allow_insecure_tls`](crate::config::Config::allow_insecure_tls), which
//! disables verification entirely and is for local development only.

use std::path::Path;

use crate::errors::{Error, Result};

/// Load additional trust-anchor certificates from a PEM bundle on disk.
///
/// Returns every certificate in the bundle so a full chain (root plus any
/// intermediates) can be pinned. The contents are never logged.
///
/// # Errors
///
/// * [`Error::Io`] if the file cannot be read.
/// * [`Error::ConfigInvalid`] if the file holds no valid PEM certificate.
pub(crate) fn load_root_certs(path: &Path) -> Result<Vec<reqwest::Certificate>> {
    let pem = std::fs::read(path).map_err(Error::Io)?;
    let certs = reqwest::Certificate::from_pem_bundle(&pem)
        .map_err(|_| Error::config_invalid("tls_ca_path is not a valid PEM certificate bundle"))?;
    if certs.is_empty() {
        return Err(Error::config_invalid(
            "tls_ca_path contains no certificates",
        ));
    }
    Ok(certs)
}
