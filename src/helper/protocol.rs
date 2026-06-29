//! The agent↔helper socket protocol: message types, framing, and token auth.
//!
//! This module is shared by both ends of the Unix Domain Socket, so it contains
//! no I/O policy beyond framing. Messages are length-prefixed (a `u32`
//! big-endian byte count followed by that many bytes of compact JSON), and the
//! body is capped at [`MAX_BODY_BYTES`] *before* allocation to bound a hostile
//! or buggy peer. Every request carries a [`PROTOCOL_VERSION`] and a capability
//! token; the helper compares the token in constant time ([`constant_time_eq`]).

use std::io::{Read, Write};

use serde::{Deserialize, Serialize};

use crate::errors::{Error, Result};

/// The socket protocol version. Bumped only on an incompatible change.
pub const PROTOCOL_VERSION: u32 = 1;

/// Maximum accepted body size for a single framed message (1 MiB).
///
/// Checked before allocating, so a malicious length prefix cannot exhaust
/// memory. The largest legitimate message is an `ApplyTrustedCaKeys` body, which
/// is far smaller than this in practice.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// An explicit, allow-listed privileged operation.
///
/// There is deliberately no generic filesystem or "run command" variant: every
/// operation maps to one reviewed action in [`super::ops`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    /// Liveness probe; the response carries the helper version.
    Ping,
    /// Ensure the managed directories exist with the expected ownership/mode.
    EnsureDirectories,
    /// Install or refresh the sshd drop-in, then validate and reload `sshd`.
    InstallSshdDropin,
    /// Atomically replace `TrustedUserCAKeys` and reload `sshd`, rolling back on
    /// failure. The new file body travels in [`Request::content`].
    ApplyTrustedCaKeys,
    /// Verify the managed files' perms/ownership and that `sshd` is healthy.
    VerifyState,
}

/// A request from the agent to the helper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    /// Must equal [`PROTOCOL_VERSION`]; the helper rejects any other value.
    pub protocol_version: u32,
    /// Capability token authenticating the caller. Never logged.
    pub token: String,
    /// The operation to perform.
    pub op: Operation,
    /// The rendered `TrustedUserCAKeys` body, required for
    /// [`Operation::ApplyTrustedCaKeys`] and absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

impl Request {
    /// Build a request with the given token and operation (no content).
    pub fn new(token: impl Into<String>, op: Operation) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            token: token.into(),
            op,
            content: None,
        }
    }

    /// Build an [`Operation::ApplyTrustedCaKeys`] request carrying `content`.
    pub fn apply(token: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            token: token.into(),
            op: Operation::ApplyTrustedCaKeys,
            content: Some(content.into()),
        }
    }
}

/// The result classification carried by a [`Response`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The operation completed successfully with no special classification.
    Ok,
    /// A new `TrustedUserCAKeys` file was applied and `sshd` reloaded.
    Applied,
    /// An apply failed and the previous file was restored.
    RolledBack,
    /// The candidate content matched what was already installed; no change.
    NotModified,
    /// A verification operation found `sshd`/state unhealthy.
    Unhealthy,
}

/// A response from the helper to the agent.
///
/// `detail` is a fixed, non-sensitive description (never a path, token, or file
/// content), safe to log on the agent side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    /// Whether the operation succeeded.
    pub ok: bool,
    /// A classification of the result.
    pub outcome: Outcome,
    /// The helper's version, populated for [`Operation::Ping`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub helper_version: Option<String>,
    /// A fixed, non-sensitive detail string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl Response {
    /// A successful response with the given outcome.
    pub fn success(outcome: Outcome) -> Self {
        Self {
            ok: true,
            outcome,
            helper_version: None,
            detail: None,
        }
    }

    /// A failure response carrying a fixed, non-sensitive detail.
    pub fn failure(outcome: Outcome, detail: impl Into<String>) -> Self {
        Self {
            ok: false,
            outcome,
            helper_version: None,
            detail: Some(detail.into()),
        }
    }
}

/// Serialise `request` to compact JSON.
///
/// # Errors
///
/// Returns [`Error::HelperProtocol`] if serialisation fails.
pub fn encode_request(request: &Request) -> Result<Vec<u8>> {
    serde_json::to_vec(request).map_err(|_| Error::HelperProtocol)
}

/// Parse a [`Request`] from compact JSON bytes.
///
/// # Errors
///
/// Returns [`Error::HelperProtocol`] if the bytes are not a valid request.
pub fn decode_request(bytes: &[u8]) -> Result<Request> {
    serde_json::from_slice(bytes).map_err(|_| Error::HelperProtocol)
}

/// Serialise `response` to compact JSON.
///
/// # Errors
///
/// Returns [`Error::HelperProtocol`] if serialisation fails.
pub fn encode_response(response: &Response) -> Result<Vec<u8>> {
    serde_json::to_vec(response).map_err(|_| Error::HelperProtocol)
}

/// Parse a [`Response`] from compact JSON bytes.
///
/// # Errors
///
/// Returns [`Error::HelperProtocol`] if the bytes are not a valid response.
pub fn decode_response(bytes: &[u8]) -> Result<Response> {
    serde_json::from_slice(bytes).map_err(|_| Error::HelperProtocol)
}

/// Write a length-prefixed frame (`u32` BE length + `body`) to `writer`.
///
/// # Errors
///
/// Returns [`Error::HelperProtocol`] if `body` exceeds [`MAX_BODY_BYTES`], or
/// [`Error::HelperUnavailable`] if the underlying write fails.
pub fn write_frame<W: Write>(writer: &mut W, body: &[u8]) -> Result<()> {
    if body.len() > MAX_BODY_BYTES {
        return Err(Error::HelperProtocol);
    }
    let len = u32::try_from(body.len()).map_err(|_| Error::HelperProtocol)?;
    writer
        .write_all(&len.to_be_bytes())
        .map_err(|_| Error::HelperUnavailable)?;
    writer
        .write_all(body)
        .map_err(|_| Error::HelperUnavailable)?;
    writer.flush().map_err(|_| Error::HelperUnavailable)?;
    Ok(())
}

/// Read a length-prefixed frame from `reader`, returning the body bytes.
///
/// The declared length is validated against [`MAX_BODY_BYTES`] before any
/// allocation.
///
/// # Errors
///
/// Returns [`Error::HelperProtocol`] if the declared length exceeds the cap, or
/// [`Error::HelperUnavailable`] if the underlying read fails (e.g. the peer
/// closed the connection mid-frame).
pub fn read_frame<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .map_err(|_| Error::HelperUnavailable)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_BODY_BYTES {
        return Err(Error::HelperProtocol);
    }
    let mut body = vec![0u8; len];
    reader
        .read_exact(&mut body)
        .map_err(|_| Error::HelperUnavailable)?;
    Ok(body)
}

/// Compare two byte slices in constant time with respect to their contents.
///
/// Returns `false` immediately for differing lengths (length is not secret),
/// but for equal lengths the comparison time does not depend on where the first
/// differing byte is, avoiding a timing side channel on the capability token.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn request_round_trips_through_frame() {
        let req = Request::apply("tok", "# keys\n");
        let body = encode_request(&req).unwrap();
        let mut buf = Vec::new();
        write_frame(&mut buf, &body).unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let read = read_frame(&mut cursor).unwrap();
        let decoded = decode_request(&read).unwrap();
        assert_eq!(decoded, req);
        assert_eq!(decoded.op, Operation::ApplyTrustedCaKeys);
        assert_eq!(decoded.content.as_deref(), Some("# keys\n"));
    }

    #[test]
    fn response_round_trips() {
        let resp = Response::failure(Outcome::RolledBack, "sshd validation failed");
        let body = encode_response(&resp).unwrap();
        assert_eq!(decode_response(&body).unwrap(), resp);
    }

    #[test]
    fn ping_request_has_no_content_field() {
        let req = Request::new("tok", Operation::Ping);
        let json = String::from_utf8(encode_request(&req).unwrap()).unwrap();
        assert!(!json.contains("content"));
        assert!(json.contains("\"op\":\"ping\""));
    }

    #[test]
    fn write_frame_rejects_oversized_body() {
        let big = vec![0u8; MAX_BODY_BYTES + 1];
        let mut buf = Vec::new();
        assert!(matches!(
            write_frame(&mut buf, &big).unwrap_err(),
            Error::HelperProtocol
        ));
    }

    #[test]
    fn read_frame_rejects_oversized_length_prefix() {
        // Declared length exceeds the cap; no allocation should occur.
        let mut buf = Vec::new();
        buf.extend_from_slice(&((MAX_BODY_BYTES as u32) + 1).to_be_bytes());
        let mut cursor = std::io::Cursor::new(buf);
        assert!(matches!(
            read_frame(&mut cursor).unwrap_err(),
            Error::HelperProtocol
        ));
    }

    #[test]
    fn read_frame_reports_unavailable_on_truncation() {
        // Length says 8 bytes but only 2 are present.
        let mut buf = Vec::new();
        buf.extend_from_slice(&8u32.to_be_bytes());
        buf.extend_from_slice(&[1, 2]);
        let mut cursor = std::io::Cursor::new(buf);
        assert!(matches!(
            read_frame(&mut cursor).unwrap_err(),
            Error::HelperUnavailable
        ));
    }

    #[test]
    fn decode_request_rejects_garbage() {
        assert!(matches!(
            decode_request(b"not json").unwrap_err(),
            Error::HelperProtocol
        ));
    }

    #[test]
    fn constant_time_eq_matches_semantics() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"", b""));
    }
}
