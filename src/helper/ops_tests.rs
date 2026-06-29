//! Unit tests for [`super`] (the privileged helper operations).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Mutex;

use super::*;
use crate::helper::protocol::Request;
use crate::identity::keypair::MachineKeypair;

/// A scriptable `SshdControl` that can fail validate/reload/is_active a fixed
/// number of times before succeeding, and records call counts.
struct MockSshd {
    validate_fail: Mutex<u32>,
    reload_fail: Mutex<u32>,
    active_fail: Mutex<u32>,
    validates: Mutex<u32>,
    reloads: Mutex<u32>,
}

impl MockSshd {
    fn healthy() -> Self {
        Self {
            validate_fail: Mutex::new(0),
            reload_fail: Mutex::new(0),
            active_fail: Mutex::new(0),
            validates: Mutex::new(0),
            reloads: Mutex::new(0),
        }
    }

    fn validate_fails_once() -> Self {
        let s = Self::healthy();
        *s.validate_fail.lock().unwrap() = 1;
        s
    }

    fn reloads(&self) -> u32 {
        *self.reloads.lock().unwrap()
    }
}

fn take(counter: &Mutex<u32>) -> bool {
    let mut remaining = counter.lock().unwrap();
    if *remaining > 0 {
        *remaining -= 1;
        true // "fail this time"
    } else {
        false
    }
}

impl SshdControl for MockSshd {
    fn validate_config(&self) -> Result<()> {
        *self.validates.lock().unwrap() += 1;
        if take(&self.validate_fail) {
            Err(Error::SshdValidationFailed)
        } else {
            Ok(())
        }
    }
    fn reload(&self) -> Result<()> {
        *self.reloads.lock().unwrap() += 1;
        if take(&self.reload_fail) {
            Err(Error::SshdInactive)
        } else {
            Ok(())
        }
    }
    fn is_active(&self) -> Result<()> {
        if take(&self.active_fail) {
            Err(Error::SshdInactive)
        } else {
            Ok(())
        }
    }
}

struct Harness {
    dir: tempfile::TempDir,
}

impl Harness {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn config(&self) -> OpsConfig {
        let root = self.dir.path();
        OpsConfig {
            trusted_ca_path: root.join("etc/ssh/mayfly/trusted_user_ca_keys"),
            dropin_path: root.join("etc/ssh/sshd_config.d/90-mayfly.conf"),
            main_sshd_config: root.join("etc/ssh/sshd_config"),
        }
    }

    /// Write a main sshd_config that Includes the drop-in directory.
    fn write_main_config_with_include(&self) {
        let cfg = self.config();
        let parent = cfg.main_sshd_config.parent().unwrap();
        std::fs::create_dir_all(parent).unwrap();
        std::fs::write(
            &cfg.main_sshd_config,
            "Port 22\nInclude /etc/ssh/sshd_config.d/*.conf\n",
        )
        .unwrap();
    }

    fn ops(&self, sshd: MockSshd) -> HelperOps<MockSshd> {
        HelperOps::new(self.config(), sshd)
    }
}

fn valid_ca_keys() -> String {
    let pk = MachineKeypair::generate()
        .unwrap()
        .public_key_openssh()
        .unwrap();
    format!("{}\n", pk.trim())
}

#[test]
fn ensure_directories_creates_managed_dirs() {
    let h = Harness::new();
    let ops = h.ops(MockSshd::healthy());
    ops.ensure_directories().unwrap();
    assert!(h.config().trusted_ca_path.parent().unwrap().is_dir());
    assert!(h.config().dropin_path.parent().unwrap().is_dir());
}

#[test]
fn apply_writes_file_and_reports_applied() {
    let h = Harness::new();
    let content = valid_ca_keys();
    let ops = h.ops(MockSshd::healthy());
    let outcome = ops.apply_trusted_ca_keys(&content).unwrap();
    assert_eq!(outcome, Outcome::Applied);
    assert_eq!(
        std::fs::read_to_string(h.config().trusted_ca_path).unwrap(),
        content
    );
}

#[test]
fn apply_is_idempotent_for_identical_content() {
    let h = Harness::new();
    let content = valid_ca_keys();
    let ops = h.ops(MockSshd::healthy());
    ops.apply_trusted_ca_keys(&content).unwrap();
    let again = ops.apply_trusted_ca_keys(&content).unwrap();
    assert_eq!(again, Outcome::NotModified);
    // Only the first apply triggered a reload.
    assert_eq!(ops.sshd.reloads(), 1);
}

#[test]
fn apply_rolls_back_on_validation_failure() {
    let h = Harness::new();
    std::fs::create_dir_all(h.config().trusted_ca_path.parent().unwrap()).unwrap();
    std::fs::write(&h.config().trusted_ca_path, "PREVIOUS\n").unwrap();

    let content = valid_ca_keys();
    let ops = h.ops(MockSshd::validate_fails_once());
    let err = ops.apply_trusted_ca_keys(&content).unwrap_err();
    assert!(matches!(err, Error::SshdValidationFailed));
    // The previous file was restored.
    assert_eq!(
        std::fs::read_to_string(h.config().trusted_ca_path).unwrap(),
        "PREVIOUS\n"
    );
}

#[test]
fn apply_rejects_unparseable_content_before_writing() {
    let h = Harness::new();
    let ops = h.ops(MockSshd::healthy());
    let err = ops
        .apply_trusted_ca_keys("ssh-dss AAAAB3NzaC1kc3M= bad-algo\n")
        .unwrap_err();
    assert!(matches!(err, Error::InvalidTrustedCa(_)));
    assert!(!h.config().trusted_ca_path.exists());
}

#[test]
fn apply_rejects_symlinked_target() {
    let h = Harness::new();
    let cfg = h.config();
    std::fs::create_dir_all(cfg.trusted_ca_path.parent().unwrap()).unwrap();
    let real = h.dir.path().join("real");
    std::fs::write(&real, "x").unwrap();
    std::os::unix::fs::symlink(&real, &cfg.trusted_ca_path).unwrap();

    let ops = h.ops(MockSshd::healthy());
    let err = ops.apply_trusted_ca_keys(&valid_ca_keys()).unwrap_err();
    assert!(matches!(err, Error::UnexpectedSymlink));
}

#[test]
fn install_dropin_writes_and_is_idempotent() {
    let h = Harness::new();
    h.write_main_config_with_include();
    let ops = h.ops(MockSshd::healthy());

    assert_eq!(ops.install_sshd_dropin().unwrap(), Outcome::Ok);
    let body = std::fs::read_to_string(h.config().dropin_path).unwrap();
    assert!(body.contains("TrustedUserCAKeys"));

    // Second call: drop-in already current.
    assert_eq!(ops.install_sshd_dropin().unwrap(), Outcome::NotModified);
}

#[test]
fn install_dropin_fails_when_include_missing() {
    let h = Harness::new();
    let cfg = h.config();
    std::fs::create_dir_all(cfg.main_sshd_config.parent().unwrap()).unwrap();
    std::fs::write(&cfg.main_sshd_config, "Port 22\n").unwrap();

    let ops = h.ops(MockSshd::healthy());
    assert!(matches!(
        ops.install_sshd_dropin().unwrap_err(),
        Error::SshdValidationFailed
    ));
    assert!(!cfg.dropin_path.exists());
}

#[test]
fn verify_state_checks_files_and_sshd() {
    let h = Harness::new();
    let ops = h.ops(MockSshd::healthy());
    ops.apply_trusted_ca_keys(&valid_ca_keys()).unwrap();
    ops.verify_state().unwrap();
}

#[test]
fn dispatch_ping_returns_version() {
    let h = Harness::new();
    let ops = h.ops(MockSshd::healthy());
    let resp = ops.dispatch(&Request::new("tok", Operation::Ping));
    assert!(resp.ok);
    assert_eq!(
        resp.helper_version.as_deref(),
        Some(env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn dispatch_apply_without_content_fails() {
    let h = Harness::new();
    let ops = h.ops(MockSshd::healthy());
    let resp = ops.dispatch(&Request::new("tok", Operation::ApplyTrustedCaKeys));
    assert!(!resp.ok);
    assert_eq!(resp.outcome, Outcome::RolledBack);
}

#[test]
fn dispatch_apply_maps_failure_to_rolled_back_response() {
    let h = Harness::new();
    let ops = h.ops(MockSshd::validate_fails_once());
    let resp = ops.dispatch(&Request::apply("tok", valid_ca_keys()));
    assert!(!resp.ok);
    assert_eq!(resp.outcome, Outcome::RolledBack);
    // Detail is the fixed, path-free error message.
    assert_eq!(
        resp.detail.as_deref(),
        Some("sshd configuration validation failed")
    );
}
