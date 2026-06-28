//! Machine identity and enrollment.
//!
//! This layer owns the machine's cryptographic identity and the enrollment
//! handshake that exchanges the machine's **public** key for a server-assigned
//! `machine_id`. It is the only place that touches private key material, and it
//! keeps that material confined: the private key never appears in logs, in
//! `Debug` output, or in the persisted machine record.
//!
//! Submodules:
//!
//! * [`keypair`] — the Ed25519 keypair (pure-Rust generation/parsing).
//! * [`machine`] — the [`MachineIdentity`](machine::MachineIdentity) model and
//!   its persisted [`MachineRecord`](machine::MachineRecord).
//! * [`enrollment`] — DTOs, validation, the [`MayflyApiClient`] abstraction (and
//!   its mock), and the [`EnrollmentService`].
//!
//! There is no request signing yet — only the identity it will use — and no HTTP
//! implementation.
//!
//! [`MayflyApiClient`]: enrollment::MayflyApiClient
//! [`EnrollmentService`]: enrollment::EnrollmentService

pub mod api_client;
pub mod enrollment;
pub mod keypair;
pub mod machine;

pub use api_client::{
    EnrollmentHttp, HttpEnrollmentClient, ReqwestEnrollmentHttp, DEFAULT_ENROLL_TIMEOUT,
    ENROLL_PATH,
};
pub use enrollment::{
    EnrollmentRequest, EnrollmentResponse, EnrollmentService, MayflyApiClient, MockMayflyApiClient,
};
pub use keypair::MachineKeypair;
pub use machine::{MachineIdentity, MachineRecord};
