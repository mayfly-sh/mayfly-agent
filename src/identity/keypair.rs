//! The machine's Ed25519 identity keypair.
//!
//! Key generation, parsing, and serialisation are pure Rust via the
//! [`ssh-key`](ssh_key) crate (RustCrypto). There is no OpenSSL and no shelling
//! out to `ssh-keygen`; the binary needs no external tools to enroll.
//!
//! The private key is held in `ssh-key`'s zeroizing types and is **never**
//! exposed in cleartext through this type's public API, nor printed by its
//! [`Debug`] implementation. Only the public key and the SHA-256 fingerprint
//! are observable.

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use ssh_key::private::KeypairData;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};
use zeroize::Zeroize;

use crate::errors::{Error, Result};

/// Comment embedded in the generated OpenSSH key files.
const KEY_COMMENT: &str = "mayfly-agent machine identity";

/// An Ed25519 machine identity keypair.
#[derive(Clone)]
pub struct MachineKeypair {
    key: PrivateKey,
}

impl MachineKeypair {
    /// Generate a fresh Ed25519 keypair using the operating system CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyGeneration`] if the underlying CSPRNG or key
    /// construction fails.
    pub fn generate() -> Result<Self> {
        let mut rng = OsRng;
        let mut key =
            PrivateKey::random(&mut rng, Algorithm::Ed25519).map_err(|_| Error::KeyGeneration)?;
        key.set_comment(KEY_COMMENT);
        Ok(Self { key })
    }

    /// Parse a keypair from an OpenSSH-format private key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyParse`] if the input is not a valid, unencrypted
    /// OpenSSH Ed25519 private key.
    pub fn from_openssh_private(pem: &str) -> Result<Self> {
        let key = PrivateKey::from_openssh(pem).map_err(|_| Error::KeyParse)?;
        if key.algorithm() != Algorithm::Ed25519 {
            return Err(Error::KeyParse);
        }
        Ok(Self { key })
    }

    /// The public key as a single OpenSSH `authorized_keys` line.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeySerialize`] if serialisation fails.
    pub fn public_key_openssh(&self) -> Result<String> {
        self.key
            .public_key()
            .to_openssh()
            .map_err(|_| Error::KeySerialize)
    }

    /// Sign `message` with the machine's Ed25519 private key, returning the raw
    /// 64-byte Ed25519 signature.
    ///
    /// The private scalar is extracted into a local buffer only for as long as
    /// it takes to construct the signer, then zeroized; the [`SigningKey`]
    /// itself zeroizes on drop. No private key material is logged or returned.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyParse`] if the underlying key is not Ed25519 (which
    /// cannot happen for a keypair built through this type's constructors).
    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64]> {
        let KeypairData::Ed25519(keypair) = self.key.key_data() else {
            return Err(Error::KeyParse);
        };
        let mut seed = keypair.private.to_bytes();
        let signing_key = SigningKey::from_bytes(&seed);
        seed.zeroize();
        Ok(signing_key.sign(message).to_bytes())
    }

    /// The SHA-256 fingerprint of the public key (`SHA256:...`).
    pub fn fingerprint(&self) -> String {
        self.key
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string()
    }

    /// Serialise the private key in OpenSSH format.
    ///
    /// Returns a zeroizing string so the cleartext is wiped from memory when
    /// dropped. Kept crate-private: callers outside the identity layer cannot
    /// extract private key material.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeySerialize`] if serialisation fails.
    pub(crate) fn to_openssh_private(&self) -> Result<zeroize::Zeroizing<String>> {
        self.key
            .to_openssh(LineEnding::LF)
            .map_err(|_| Error::KeySerialize)
    }
}

/// Validate that `value` is a well-formed OpenSSH **Ed25519** public key line.
///
/// Used to validate both the agent's own public key before sending it and, when
/// validating server responses, the server's identity key.
///
/// # Errors
///
/// Returns [`Error::MalformedPublicKey`] if the value is not a valid Ed25519
/// public key.
pub fn validate_ed25519_public_key(value: &str) -> Result<()> {
    if value.chars().any(|c| c.is_control()) {
        return Err(Error::MalformedPublicKey);
    }
    let key = ssh_key::PublicKey::from_openssh(value).map_err(|_| Error::MalformedPublicKey)?;
    if key.algorithm() != Algorithm::Ed25519 {
        return Err(Error::MalformedPublicKey);
    }
    Ok(())
}

impl std::fmt::Debug for MachineKeypair {
    /// Print only the public fingerprint; never any private key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MachineKeypair")
            .field("fingerprint", &self.fingerprint())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn generate_produces_ed25519_key() {
        let kp = MachineKeypair::generate().unwrap();
        let public = kp.public_key_openssh().unwrap();
        assert!(public.starts_with("ssh-ed25519 "));
        assert!(kp.fingerprint().starts_with("SHA256:"));
    }

    #[test]
    fn generated_keys_are_unique() {
        let a = MachineKeypair::generate().unwrap();
        let b = MachineKeypair::generate().unwrap();
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn private_key_round_trips() {
        let kp = MachineKeypair::generate().unwrap();
        let pem = kp.to_openssh_private().unwrap();
        let reparsed = MachineKeypair::from_openssh_private(&pem).unwrap();
        assert_eq!(kp.fingerprint(), reparsed.fingerprint());
        assert_eq!(
            kp.public_key_openssh().unwrap(),
            reparsed.public_key_openssh().unwrap()
        );
    }

    #[test]
    fn rejects_corrupt_private_key() {
        assert!(matches!(
            MachineKeypair::from_openssh_private("not a key").unwrap_err(),
            Error::KeyParse
        ));
    }

    #[test]
    fn validates_own_public_key() {
        let kp = MachineKeypair::generate().unwrap();
        validate_ed25519_public_key(&kp.public_key_openssh().unwrap()).unwrap();
    }

    #[test]
    fn rejects_malformed_public_key() {
        for bad in ["", "ssh-ed25519", "ssh-ed25519 not-base64!!", "garbage"] {
            assert!(matches!(
                validate_ed25519_public_key(bad).unwrap_err(),
                Error::MalformedPublicKey
            ));
        }
    }

    #[test]
    fn rejects_non_ed25519_public_key() {
        // A syntactically valid RSA key line must be rejected as not Ed25519.
        let rsa = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDExample test";
        assert!(matches!(
            validate_ed25519_public_key(rsa).unwrap_err(),
            Error::MalformedPublicKey
        ));
    }

    #[test]
    fn debug_never_leaks_private_key() {
        let kp = MachineKeypair::generate().unwrap();
        let pem = kp.to_openssh_private().unwrap();
        let debug = format!("{kp:?}");
        assert!(debug.contains("fingerprint"));
        assert!(!debug.contains("PRIVATE KEY"));
        assert!(!debug.contains(pem.trim()));
    }
}
