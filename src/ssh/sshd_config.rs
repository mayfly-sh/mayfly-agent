//! Pure inspection and rendering of the sshd `TrustedUserCAKeys` drop-in.
//!
//! This module performs **no I/O**: it only renders the canonical drop-in text
//! and parses provided configuration text. Writing the drop-in, validating with
//! `sshd -t`, and reloading are performed by the privileged `mayfly-helper` (a
//! separate repository); the agent uses this module for startup SSH-compatibility
//! checks (`Include` detection) and to render content it sends over IPC.
//!
//! Operations:
//!
//! * [`render_directive`] — the canonical `TrustedUserCAKeys <path>` line;
//! * [`render_dropin`] — the full managed drop-in file body;
//! * [`find_trusted_user_ca_keys`] — locate the effective directive value;
//! * [`includes_dropin_dir`] — detect whether the main config `Include`s the
//!   `sshd_config.d` drop-in directory (so a missing `Include` is reported
//!   clearly instead of silently ignored).

use std::path::Path;

/// The sshd configuration keyword this daemon manages.
pub const DIRECTIVE_KEYWORD: &str = "TrustedUserCAKeys";

/// The conventional drop-in directory modern OpenSSH includes by default.
pub const DROPIN_DIR: &str = "/etc/ssh/sshd_config.d";

/// The drop-in file name this daemon manages. The `90-` prefix orders it late
/// so it takes precedence over earlier drop-ins for the keyword it sets.
pub const DROPIN_FILENAME: &str = "90-mayfly.conf";

/// Render the canonical `TrustedUserCAKeys <path>` directive line.
///
/// The returned string has no trailing newline. This only renders text; it does
/// not write anything.
pub fn render_directive(trusted_ca_path: &Path) -> String {
    format!("{} {}", DIRECTIVE_KEYWORD, trusted_ca_path.display())
}

/// Render the full managed sshd drop-in body (with trailing newline).
///
/// The body is deterministic for a given `trusted_ca_path`, so the helper can
/// compare it against the on-disk drop-in to avoid needless rewrites/reloads. It
/// carries a clear "managed — do not edit" banner.
pub fn render_dropin(trusted_ca_path: &Path) -> String {
    format!(
        "# Managed by mayfly-agent. Do not edit; changes are overwritten.\n\
         # Configures the Mayfly-managed OpenSSH user-certificate trust anchor.\n\
         {}\n",
        render_directive(trusted_ca_path)
    )
}

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

/// Find the effective `TrustedUserCAKeys` value in `config_text`, if present.
///
/// sshd applies the *first* matching directive, and keywords are
/// case-insensitive. Commented (`#`) and blank lines are ignored. Returns the
/// directive's value (the remainder of the line) with surrounding whitespace
/// trimmed.
pub fn find_trusted_user_ca_keys(config_text: &str) -> Option<String> {
    for line in config_text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Split into the keyword and the rest of the line. sshd accepts either
        // whitespace or `=` between a keyword and its value.
        let (keyword, rest) = match trimmed.split_once(|c: char| c.is_whitespace() || c == '=') {
            Some(pair) => pair,
            None => continue,
        };

        if keyword.eq_ignore_ascii_case(DIRECTIVE_KEYWORD) {
            let value = rest.trim().trim_start_matches('=').trim();
            if value.is_empty() {
                return None;
            }
            return Some(value.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn renders_canonical_directive() {
        let line = render_directive(Path::new("/etc/ssh/mayfly_ca.pub"));
        assert_eq!(line, "TrustedUserCAKeys /etc/ssh/mayfly_ca.pub");
    }

    #[test]
    fn finds_directive_value() {
        let text = "Port 22\nTrustedUserCAKeys /etc/ssh/mayfly_ca.pub\n";
        assert_eq!(
            find_trusted_user_ca_keys(text).as_deref(),
            Some("/etc/ssh/mayfly_ca.pub")
        );
    }

    #[test]
    fn keyword_is_case_insensitive() {
        let text = "trustedusercakeys /etc/ssh/ca.pub\n";
        assert_eq!(
            find_trusted_user_ca_keys(text).as_deref(),
            Some("/etc/ssh/ca.pub")
        );
    }

    #[test]
    fn handles_leading_whitespace_and_tabs() {
        let text = "   \tTrustedUserCAKeys\t/etc/ssh/ca.pub\n";
        assert_eq!(
            find_trusted_user_ca_keys(text).as_deref(),
            Some("/etc/ssh/ca.pub")
        );
    }

    #[test]
    fn ignores_commented_directives() {
        let text = "# TrustedUserCAKeys /etc/ssh/old.pub\nPort 22\n";
        assert_eq!(find_trusted_user_ca_keys(text), None);
    }

    #[test]
    fn returns_first_match() {
        let text = "TrustedUserCAKeys /first.pub\nTrustedUserCAKeys /second.pub\n";
        assert_eq!(
            find_trusted_user_ca_keys(text).as_deref(),
            Some("/first.pub")
        );
    }

    #[test]
    fn absent_directive_returns_none() {
        let text = "Port 22\nPermitRootLogin no\n";
        assert_eq!(find_trusted_user_ca_keys(text), None);
    }

    #[test]
    fn keyword_without_value_returns_none() {
        let text = "TrustedUserCAKeys\n";
        assert_eq!(find_trusted_user_ca_keys(text), None);
    }

    #[test]
    fn renders_managed_dropin_body() {
        let body = render_dropin(Path::new("/etc/ssh/mayfly/trusted_user_ca_keys"));
        assert!(body.starts_with("# Managed by mayfly-agent"));
        assert!(body.contains("TrustedUserCAKeys /etc/ssh/mayfly/trusted_user_ca_keys"));
        assert!(body.ends_with('\n'));
        // The drop-in must itself parse as containing the directive we set.
        assert_eq!(
            find_trusted_user_ca_keys(&body).as_deref(),
            Some("/etc/ssh/mayfly/trusted_user_ca_keys")
        );
    }

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
