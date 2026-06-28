//! General Linux host operations.
//!
//! These are read-only inspections of the running process and host. They never
//! mutate system state.

use std::ffi::CStr;
use std::net::UdpSocket;

use crate::errors::{Error, Result};

/// Read-only facts about the host, gathered for enrollment and heartbeats.
///
/// All fields are best-effort and non-secret. The IP is the source address the
/// kernel would select to reach the public internet; it is informational only
/// (the agent is authenticated by its signing key, never by IP).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFacts {
    /// The host's node name (`uname` nodename).
    pub hostname: String,
    /// Operating system (`std::env::consts::OS`, e.g. `linux`).
    pub os: String,
    /// Kernel release string (`uname` release).
    pub kernel: String,
    /// CPU architecture (`std::env::consts::ARCH`).
    pub arch: String,
    /// Best-effort self-reported IP address, or `0.0.0.0` if undeterminable.
    pub ip: String,
}

/// Gather read-only [`HostFacts`] about the running host.
///
/// This performs no privileged action and mutates nothing. The IP probe opens a
/// UDP socket and *connects* it (which sends no packets) purely to learn the
/// source address the kernel would use; it falls back to `0.0.0.0` offline.
pub fn host_facts() -> HostFacts {
    let uname = rustix::system::uname();
    HostFacts {
        hostname: cstr_to_string(uname.nodename()),
        os: std::env::consts::OS.to_string(),
        kernel: cstr_to_string(uname.release()),
        arch: std::env::consts::ARCH.to_string(),
        ip: local_ip().unwrap_or_else(|| "0.0.0.0".to_string()),
    }
}

/// Convert a C string to an owned [`String`], replacing invalid UTF-8.
fn cstr_to_string(value: &CStr) -> String {
    value.to_string_lossy().into_owned()
}

/// Best-effort determination of the local source IP.
///
/// Binds and connects a UDP socket to a non-routable documentation address
/// ([RFC 5737] TEST-NET-1). UDP `connect` only records the default peer and the
/// kernel-chosen source address; no datagram is transmitted. Returns `None` when
/// no source address can be determined (e.g. no network).
///
/// [RFC 5737]: https://datatracker.ietf.org/doc/html/rfc5737
fn local_ip() -> Option<String> {
    let socket = UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    socket.connect(("192.0.2.1", 80)).ok()?;
    let ip = socket.local_addr().ok()?.ip();
    if ip.is_unspecified() {
        None
    } else {
        Some(ip.to_string())
    }
}

/// Return the effective user id of the current process.
pub fn effective_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// Validate that the process is running as root (effective uid 0).
///
/// # Errors
///
/// Returns [`Error::NotRoot`] if the effective uid is not 0.
pub fn validate_root() -> Result<()> {
    let euid = effective_uid();
    if euid == 0 {
        Ok(())
    } else {
        tracing::warn!(euid, "process is not running as root");
        Err(Error::NotRoot)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn effective_uid_matches_validate_root() {
        let euid = effective_uid();
        let result = validate_root();
        if euid == 0 {
            assert!(result.is_ok());
        } else {
            assert!(matches!(result.unwrap_err(), Error::NotRoot));
        }
    }

    #[test]
    fn host_facts_reports_consistent_os_and_arch() {
        let facts = host_facts();
        assert_eq!(facts.os, std::env::consts::OS);
        assert_eq!(facts.arch, std::env::consts::ARCH);
        // hostname/kernel are environment-dependent but should be populated.
        assert!(!facts.kernel.is_empty());
        // ip is always at least the fallback.
        assert!(!facts.ip.is_empty());
    }
}
