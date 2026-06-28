//! The authenticated agent↔server protocol (agent side).
//!
//! Every authenticated request is signed with the machine's Ed25519 identity
//! key — there are no API keys or shared secrets. This module provides:
//!
//! * [`signing`] — the canonical string, body hashing, nonce generation, and
//!   request signing (the byte-for-byte mirror of the server's verifier).
//! * [`heartbeat`] — the [`heartbeat::HeartbeatClient`] that signs and sends a
//!   heartbeat over a pluggable [`heartbeat::HeartbeatTransport`].

pub mod heartbeat;
pub mod signing;

pub use heartbeat::{
    HeartbeatClient, HeartbeatRequest, HeartbeatResponse, HeartbeatTransport, HttpRequest,
    HttpResponse, ReqwestTransport, HEARTBEAT_PATH,
};
pub use signing::{
    body_sha256_hex, canonical_string, generate_nonce, sign_request, SignedHeaders, SIGNING_DOMAIN,
};
