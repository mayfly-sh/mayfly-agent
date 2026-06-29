//! SSH-facing data models.
//!
//! This module contains pure, read-only parsing and validation used by the
//! (unprivileged) agent:
//!
//! * [`trusted_ca`] — validate a `TrustedUserCAKeys` body before delegating its
//!   privileged application to the helper (defence in depth);
//! * [`sshd_config`] — a read-only startup check that the main `sshd_config`
//!   `Include`s the drop-in directory.
//!
//! Nothing here performs I/O against the real system, fetches keys from the
//! network, or modifies `sshd_config`. Rendering, writing, and reloading the
//! managed drop-in are owned entirely by the privileged `mayfly-helper`.

pub mod sshd_config;
pub mod trusted_ca;
