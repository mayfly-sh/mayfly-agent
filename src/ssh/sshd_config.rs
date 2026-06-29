//! Pure inspection of the sshd configuration for startup SSH-compatibility.
//!
//! This module performs **no I/O**: it only parses provided configuration text.
//! Rendering, writing, validating (`sshd -t`), and reloading the managed
//! `TrustedUserCAKeys` drop-in are all owned by the privileged `mayfly-helper`
//! (a separate repository). The agent uses this module solely for a read-only
//! startup check:
//!
//! * [`includes_dropin_dir`] — detect whether the main config `Include`s the
//!   `sshd_config.d` drop-in directory (so a missing `Include` is reported
//!   clearly instead of silently ignored).

/// The conventional drop-in directory modern OpenSSH includes by default.
pub const DROPIN_DIR: &str = "/etc/ssh/sshd_config.d";

/// Detect whether `config_text` `Include`s the drop-in directory `dropin_dir`.
///
/// Modern OpenSSH ships `Include /etc/ssh/sshd_config.d/*.conf` in the default
/// `sshd_config`; without such an `Include`, a drop-in file is inert. We detect
/// an `Include` whose (whitespace-separated) values reference `dropin_dir` so a
/// missing include can be reported as an actionable error rather than silently
/// producing a no-op configuration. Commented and blank lines are ignored;
/// keywords are case-insensitive.
pub fn includes_dropin_dir(config_text: &str, dropin_dir: &str) -> bool {
    let needle = dropin_dir.trim_end_matches('/');
    for line in config_text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((keyword, rest)) = trimmed.split_once(char::is_whitespace) else {
            continue;
        };
        if !keyword.eq_ignore_ascii_case("Include") {
            continue;
        }
        // An Include may list several glob patterns. A reference counts if any
        // pattern's directory component matches the drop-in directory.
        for pattern in rest.split_whitespace() {
            let dir = pattern
                .rsplit_once('/')
                .map(|(dir, _file)| dir)
                .unwrap_or(pattern);
            if dir.trim_end_matches('/') == needle {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn detects_include_of_dropin_dir() {
        let text = "Port 22\nInclude /etc/ssh/sshd_config.d/*.conf\n";
        assert!(includes_dropin_dir(text, DROPIN_DIR));
        assert!(includes_dropin_dir(text, "/etc/ssh/sshd_config.d/"));
    }

    #[test]
    fn detects_include_among_multiple_patterns() {
        let text = "Include /etc/ssh/other.d/*.conf /etc/ssh/sshd_config.d/*.conf\n";
        assert!(includes_dropin_dir(text, DROPIN_DIR));
    }

    #[test]
    fn missing_include_is_detected() {
        let text = "Port 22\nPermitRootLogin no\n";
        assert!(!includes_dropin_dir(text, DROPIN_DIR));

        // A commented Include does not count.
        let commented = "# Include /etc/ssh/sshd_config.d/*.conf\n";
        assert!(!includes_dropin_dir(commented, DROPIN_DIR));

        // An Include of a different directory does not count.
        let other = "Include /etc/ssh/other.d/*.conf\n";
        assert!(!includes_dropin_dir(other, DROPIN_DIR));
    }

    #[test]
    fn include_keyword_is_case_insensitive() {
        let text = "include /etc/ssh/sshd_config.d/*.conf\n";
        assert!(includes_dropin_dir(text, DROPIN_DIR));
    }
}
