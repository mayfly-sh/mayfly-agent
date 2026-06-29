//! The `mayfly-helper` Unix Domain Socket server.
//!
//! Binds a stream socket (restricted to mode `0660`), accepts one request per
//! connection, authenticates it (protocol version + constant-time capability
//! token), dispatches to [`HelperOps`], and replies with a single framed
//! [`Response`]. The accept loop is interruptible via a shared stop flag so the
//! process can shut down cleanly on `SIGTERM`/`SIGINT`.
//!
//! Authentication failures receive an explicit (non-sensitive) response and the
//! connection is closed; the helper never performs an operation for a request it
//! has not authenticated.

use std::io::Read;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::errors::{Error, Result};
use crate::helper::ops::HelperOps;
use crate::helper::protocol::{self, Outcome, Request, Response, MAX_BODY_BYTES, PROTOCOL_VERSION};
use crate::helper::sshd_control::SshdControl;

/// Socket file permission bits: owner+group read/write, no access for others.
const SOCKET_MODE: u32 = 0o660;

/// How long to nap between accept polls while idle (keeps shutdown responsive).
const ACCEPT_POLL: Duration = Duration::from_millis(100);

/// Per-connection read/write timeout, so a stalled peer cannot pin a slot.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// The privileged socket server.
pub struct HelperServer<C: SshdControl> {
    socket_path: PathBuf,
    token: String,
    ops: HelperOps<C>,
    socket_gid: Option<u32>,
}

impl<C: SshdControl> HelperServer<C> {
    /// Construct a server that will listen at `socket_path`, authenticate with
    /// `token`, and execute `ops`.
    pub fn new(socket_path: PathBuf, token: String, ops: HelperOps<C>) -> Self {
        Self {
            socket_path,
            token,
            ops,
            socket_gid: None,
        }
    }

    /// Set the group (by numeric gid) that should own the socket file so the
    /// unprivileged agent's group can connect (mode `0660`). When unset, the
    /// socket keeps its default group (e.g. set via a setgid `RuntimeDirectory`).
    pub fn with_socket_group(mut self, gid: Option<u32>) -> Self {
        self.socket_gid = gid;
        self
    }

    /// Bind the socket and serve until `stop` becomes `true`.
    ///
    /// The socket file is removed if it already exists (a stale socket from a
    /// previous run), recreated, and its permissions tightened to
    /// [`SOCKET_MODE`] before any request is accepted.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the socket cannot be bound or its permissions
    /// set.
    pub fn run(&self, stop: &AtomicBool) -> Result<()> {
        let listener = self.bind()?;
        listener.set_nonblocking(true).map_err(Error::Io)?;
        tracing::info!("mayfly-helper listening");

        while !stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _addr)) => {
                    if let Err(err) = self.handle_connection(stream) {
                        tracing::warn!(error = %err, "helper connection error");
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(ACCEPT_POLL);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "helper accept failed");
                    std::thread::sleep(ACCEPT_POLL);
                }
            }
        }

        tracing::info!("mayfly-helper shutting down");
        let _ = std::fs::remove_file(&self.socket_path);
        Ok(())
    }

    fn bind(&self) -> Result<UnixListener> {
        if let Some(parent) = self.socket_path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::create_dir_all(parent).map_err(Error::Io)?;
            }
        }
        // Remove a stale socket so bind does not fail with EADDRINUSE.
        match std::fs::remove_file(&self.socket_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::Io(e)),
        }
        let listener = UnixListener::bind(&self.socket_path).map_err(Error::Io)?;
        if let Some(gid) = self.socket_gid {
            std::os::unix::fs::chown(&self.socket_path, None, Some(gid)).map_err(Error::Io)?;
        }
        set_socket_mode(&self.socket_path)?;
        Ok(listener)
    }

    /// Read one request, authenticate, dispatch, and reply.
    fn handle_connection(&self, mut stream: UnixStream) -> Result<()> {
        stream
            .set_read_timeout(Some(IO_TIMEOUT))
            .map_err(Error::Io)?;
        stream
            .set_write_timeout(Some(IO_TIMEOUT))
            .map_err(Error::Io)?;

        let response = match self.read_request(&mut stream) {
            Ok(request) => self.authenticate_and_dispatch(&request),
            Err(_) => Response::failure(Outcome::Unhealthy, "protocol error"),
        };

        let body = protocol::encode_response(&response)?;
        protocol::write_frame(&mut stream, &body)
    }

    fn read_request(&self, stream: &mut impl Read) -> Result<Request> {
        let body = protocol::read_frame(stream)?;
        if body.len() > MAX_BODY_BYTES {
            return Err(Error::HelperProtocol);
        }
        protocol::decode_request(&body)
    }

    fn authenticate_and_dispatch(&self, request: &Request) -> Response {
        if request.protocol_version != PROTOCOL_VERSION {
            tracing::warn!(
                version = request.protocol_version,
                "rejected request: unsupported protocol version"
            );
            return Response::failure(Outcome::Unhealthy, "unsupported protocol version");
        }
        if !protocol::constant_time_eq(request.token.as_bytes(), self.token.as_bytes()) {
            tracing::warn!(op = ?request.op, "rejected request: unauthenticated");
            return Response::failure(Outcome::Unhealthy, "unauthenticated");
        }
        tracing::info!(op = ?request.op, "helper executing operation");
        self.ops.dispatch(request)
    }
}

/// Tighten the socket file's permissions to [`SOCKET_MODE`].
fn set_socket_mode(path: &Path) -> Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(SOCKET_MODE)).map_err(Error::Io)
}
