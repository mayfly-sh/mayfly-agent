//! The authenticated agent↔server protocol (agent side).
//!
//! Every authenticated request is signed with the machine's Ed25519 identity
//! key — there are no API keys or shared secrets. This module provides:
//!
//! * [`signing`] — the canonical string, body hashing, nonce generation, and
//!   request signing (the byte-for-byte mirror of the server's verifier).
//! * [`heartbeat`] — the [`heartbeat::HeartbeatClient`] that signs and sends a
//!   heartbeat over a pluggable [`heartbeat::HeartbeatTransport`].
//! * [`ca_bundle`] — the pure CA-bundle model: parsing, validation, canonical
//!   fingerprinting, and `TrustedUserCAKeys` rendering.
//! * [`ca_sync`] — the [`ca_sync::CaSyncService`] that fetches, verifies, and
//!   then delegates the privileged apply (via the [`ca_sync::BundleApplier`]
//!   port) to the `mayfly-helper`, persists, and acknowledges a bundle.

pub mod ca_bundle;
pub mod ca_sync;
pub mod heartbeat;
pub mod signing;

pub use ca_bundle::{
    canonical_json, canonical_signing_payload, compute_fingerprint, CaBundle, CaBundleKey,
    CaBundleResponse, CA_BUNDLE_ACK_PATH, CA_BUNDLE_PATH, HEADER_ETAG, HEADER_IF_NONE_MATCH,
    MAX_KEYS, MIN_KEYS, SIGNATURE_ALGORITHM, SUPPORTED_BUNDLE_VERSION,
};
pub use ca_sync::{
    AckReport, BundleApplier, BundleApplyOutcome, CaBundleTransport, CaSyncService, SyncOutcome,
};
pub use heartbeat::{
    HeartbeatClient, HeartbeatRequest, HeartbeatResponse, HeartbeatTransport, HttpRequest,
    HttpResponse, ReqwestTransport, HEARTBEAT_PATH,
};
pub use signing::{
    body_sha256_hex, canonical_string, generate_nonce, sign_request, SignedHeaders, SIGNING_DOMAIN,
};
