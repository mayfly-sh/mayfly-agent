//! Read-only inspection and rendering of the sshd `TrustedUserCAKeys` directive.
//!
//! This module **never** writes to or modifies any sshd configuration file. It
//! provides two pure operations:
//!
//! * [`render_directive`] — produce the canonical directive line the daemon
//!   intends to manage;
//! * [`find_trusted_user_ca_keys`] — locate the effective `TrustedUserCAKeys`
//!   value in some provided sshd configuration text.
//!
//! Applying these (writing the drop-in, validating with `sshd -t`, reloading)
//! is out of scope for this phase.

use std::path::Path;

/// The sshd configuration keyword this daemon manages.
pub const DIRECTIVE_KEYWORD: &str = "TrustedUserCAKeys";

/// Render the canonical `TrustedUserCAKeys <path>` directive line.
///
/// The returned string has no trailing newline. This only renders text; it does
/// not write anything.
pub fn render_directive(trusted_ca_path: &Path) -> String {
    format!("{} {}", DIRECTIVE_KEYWORD, trusted_ca_path.display())
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
}
