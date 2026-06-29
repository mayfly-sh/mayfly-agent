//! The agent-side client for the privileged helper.
//!
//! The agent connects to the helper's socket per call, sends one authenticated
//! request, and reads one response. The capability token is loaded from a
//! root-owned, group-readable file; it is never logged. Transport and
//! authentication failures map to the crate's path-free [`Error`] variants.

use std::io::Read as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::errors::{Error, Result};
use crate::helper::protocol::{self, Operation, Outcome, Request, Response};

/// Per-call connect/read/write timeout.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// A thin client over the helper's Unix Domain Socket.
#[derive(Debug, Clone)]
pub struct HelperClient {
    socket_path: PathBuf,
    token: String,
}

impl HelperClient {
    /// Construct from an explicit socket path and token.
    pub fn new(socket_path: PathBuf, token: String) -> Self {
        Self { socket_path, token }
    }

    /// Construct by reading the capability token from `token_path`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the token file cannot be read.
    pub fn from_paths(socket_path: PathBuf, token_path: &Path) -> Result<Self> {
        let token = std::fs::read_to_string(token_path).map_err(Error::Io)?;
        Ok(Self::new(socket_path, token.trim().to_string()))
    }

    /// Send `request` and return the helper's response.
    ///
    /// # Errors
    ///
    /// * [`Error::HelperUnavailable`] if the socket cannot be connected or the
    ///   connection drops.
    /// * [`Error::HelperProtocol`] if the response is malformed.
    pub fn call(&self, request: &Request) -> Result<Response> {
        let mut stream =
            UnixStream::connect(&self.socket_path).map_err(|_| Error::HelperUnavailable)?;
        stream
            .set_read_timeout(Some(IO_TIMEOUT))
            .map_err(|_| Error::HelperUnavailable)?;
        stream
            .set_write_timeout(Some(IO_TIMEOUT))
            .map_err(|_| Error::HelperUnavailable)?;

        let body = protocol::encode_request(request)?;
        protocol::write_frame(&mut stream, &body)?;

        let response_body = protocol::read_frame(&mut stream)?;
        // Drain politely; the server sends exactly one frame then closes.
        let mut sink = Vec::new();
        let _ = stream.take(0).read_to_end(&mut sink);
        protocol::decode_response(&response_body)
    }

    /// Probe the helper, returning its reported version.
    ///
    /// # Errors
    ///
    /// See [`HelperClient::call`]; also [`Error::HelperOperationFailed`] if the
    /// helper replies without a version.
    pub fn ping(&self) -> Result<String> {
        let resp = self.call(&Request::new(&self.token, Operation::Ping))?;
        check_ok(&resp)?;
        resp.helper_version.ok_or(Error::HelperOperationFailed)
    }

    /// Ensure the managed directories exist.
    ///
    /// # Errors
    ///
    /// See [`HelperClient::call`] and [`check_ok`].
    pub fn ensure_directories(&self) -> Result<()> {
        let resp = self.call(&Request::new(&self.token, Operation::EnsureDirectories))?;
        check_ok(&resp).map(|_| ())
    }

    /// Install or refresh the sshd drop-in.
    ///
    /// # Errors
    ///
    /// See [`HelperClient::call`] and [`check_ok`].
    pub fn install_sshd_dropin(&self) -> Result<Outcome> {
        let resp = self.call(&Request::new(&self.token, Operation::InstallSshdDropin))?;
        check_ok(&resp)
    }

    /// Atomically apply a new `TrustedUserCAKeys` body.
    ///
    /// # Errors
    ///
    /// See [`HelperClient::call`] and [`check_ok`]. A rollback is surfaced as
    /// [`Error::HelperOperationFailed`].
    pub fn apply_trusted_ca_keys(&self, content: &str) -> Result<Outcome> {
        let resp = self.call(&Request::apply(&self.token, content))?;
        check_ok(&resp)
    }

    /// Verify the managed files and that `sshd` is healthy.
    ///
    /// # Errors
    ///
    /// See [`HelperClient::call`] and [`check_ok`].
    pub fn verify_state(&self) -> Result<()> {
        let resp = self.call(&Request::new(&self.token, Operation::VerifyState))?;
        check_ok(&resp).map(|_| ())
    }
}

/// Map a [`Response`] to a [`Result`], translating the helper's failure detail
/// into the appropriate path-free [`Error`].
fn check_ok(resp: &Response) -> Result<Outcome> {
    if resp.ok {
        return Ok(resp.outcome);
    }
    match resp.detail.as_deref() {
        Some("unauthenticated") => Err(Error::HelperUnauthenticated),
        _ => Err(Error::HelperOperationFailed),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use super::*;
    use crate::helper::ops::{HelperOps, OpsConfig};
    use crate::helper::server::HelperServer;
    use crate::helper::sshd_control::{SshdControlConfig, SystemSshdControl};

    /// Spawn a helper server on a temp socket; return (client, stop, join).
    fn spawn_server(
        token: &str,
    ) -> (
        tempfile::TempDir,
        PathBuf,
        Arc<AtomicBool>,
        std::thread::JoinHandle<()>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("helper.sock");
        let token = token.to_string();
        let ops_config = OpsConfig {
            trusted_ca_path: dir.path().join("etc/ssh/mayfly/trusted_user_ca_keys"),
            dropin_path: dir.path().join("etc/ssh/sshd_config.d/90-mayfly.conf"),
            main_sshd_config: dir.path().join("etc/ssh/sshd_config"),
        };
        // Ping does not touch sshd; SystemSshdControl with missing binaries is
        // sufficient for the transport/auth tests here.
        let sshd = SystemSshdControl::new(SshdControlConfig::default());
        let ops = HelperOps::new(ops_config, sshd);
        let server = HelperServer::new(socket.clone(), token, ops);

        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        let socket_thread = socket.clone();
        let handle = std::thread::spawn(move || {
            server.run(&stop_thread).unwrap();
            let _ = socket_thread;
        });

        // Wait for the socket to appear so the client does not race the bind.
        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        (dir, socket, stop, handle)
    }

    #[test]
    fn ping_round_trip_returns_version() {
        let (_dir, socket, stop, handle) = spawn_server("secret-token");
        let client = HelperClient::new(socket, "secret-token".to_string());

        let version = client.ping().unwrap();
        assert_eq!(version, env!("CARGO_PKG_VERSION"));

        stop.store(true, Ordering::Relaxed);
        handle.join().unwrap();
    }

    #[test]
    fn wrong_token_is_rejected_as_unauthenticated() {
        let (_dir, socket, stop, handle) = spawn_server("real-token");
        let client = HelperClient::new(socket, "wrong-token".to_string());

        let err = client.ping().unwrap_err();
        assert!(matches!(err, Error::HelperUnauthenticated));

        stop.store(true, Ordering::Relaxed);
        handle.join().unwrap();
    }

    #[test]
    fn connect_to_missing_socket_is_unavailable() {
        let client = HelperClient::new(PathBuf::from("/nonexistent/helper.sock"), "t".to_string());
        assert!(matches!(
            client.ping().unwrap_err(),
            Error::HelperUnavailable
        ));
    }

    #[test]
    fn from_paths_reads_token_file() {
        let dir = tempfile::tempdir().unwrap();
        let token_path = dir.path().join("helper.token");
        std::fs::write(&token_path, "file-token\n").unwrap();
        let client = HelperClient::from_paths(dir.path().join("helper.sock"), &token_path).unwrap();
        assert_eq!(client.token, "file-token");
    }
}
