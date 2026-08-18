//! ML-KEM-768 and ML-DSA-65 provider for the ASTRA-PQ research prototype.
//!
//! The implementation uses the safe `oqs` wrapper over vendored liboqs. It is
//! intended for experimental evaluation and does not assert production readiness.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use oqs::{kem, sig};
use std::fmt;
use std::sync::Once;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

const MAX_SIGNED_MESSAGE_BYTES: usize = 1_048_576;
static OQS_INIT: Once = Once::new();

/// Secret byte storage that is erased when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrows secret material for an immediate cryptographic operation.
    ///
    /// Callers must not log, serialize, clone, or persist the returned bytes.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }

    /// Returns the secret length without exposing its contents.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the secret buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretBytes")
            .field("length", &self.0.len())
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

/// ML-KEM-768 key pair.
#[derive(Debug)]
pub struct KemKeyPair {
    public_key: Vec<u8>,
    secret_key: SecretBytes,
}

impl KemKeyPair {
    /// Returns the public encapsulation key.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Returns the protected decapsulation key wrapper.
    #[must_use]
    pub const fn secret_key(&self) -> &SecretBytes {
        &self.secret_key
    }
}

/// ML-DSA-65 key pair.
#[derive(Debug)]
pub struct SignatureKeyPair {
    public_key: Vec<u8>,
    secret_key: SecretBytes,
}

impl SignatureKeyPair {
    /// Returns the public verification key.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Returns the protected signing key wrapper.
    #[must_use]
    pub const fn secret_key(&self) -> &SecretBytes {
        &self.secret_key
    }
}

/// Result of ML-KEM encapsulation.
#[derive(Debug)]
pub struct KemEncapsulation {
    ciphertext: Vec<u8>,
    shared_secret: SecretBytes,
}

impl KemEncapsulation {
    /// Returns the public KEM ciphertext.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Returns the protected shared-secret wrapper.
    #[must_use]
    pub const fn shared_secret(&self) -> &SecretBytes {
        &self.shared_secret
    }
}

/// Non-secret provider properties recorded with experiment results.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderMetadata {
    /// KEM algorithm name.
    pub kem_algorithm: &'static str,
    /// Signature algorithm name.
    pub signature_algorithm: &'static str,
    /// liboqs KEM implementation version.
    pub kem_implementation: &'static str,
    /// liboqs signature implementation version.
    pub signature_implementation: &'static str,
    /// Claimed NIST security level for ML-KEM-768.
    pub kem_nist_level: u8,
    /// Claimed NIST security level for ML-DSA-65.
    pub signature_nist_level: u8,
}

/// Safe ASTRA-PQ wrapper around the selected liboqs algorithms.
pub struct PqProvider {
    kem: kem::Kem,
    signature: sig::Sig,
}

impl PqProvider {
    /// Initializes ML-KEM-768 and ML-DSA-65.
    pub fn new() -> Result<Self, CryptoError> {
        OQS_INIT.call_once(oqs::init);
        let kem = kem::Kem::new(kem::Algorithm::MlKem768)
            .map_err(|error| CryptoError::Initialization(format!("{error:?}")))?;
        let signature = sig::Sig::new(sig::Algorithm::MlDsa65)
            .map_err(|error| CryptoError::Initialization(format!("{error:?}")))?;
        if !kem.is_ind_cca() {
            return Err(CryptoError::UnexpectedProviderProperty(
                "ML-KEM backend does not report IND-CCA security",
            ));
        }
        Ok(Self { kem, signature })
    }

    /// Returns non-secret provider metadata for reproducibility records.
    #[must_use]
    pub fn metadata(&self) -> ProviderMetadata {
        ProviderMetadata {
            kem_algorithm: self.kem.algorithm().name(),
            signature_algorithm: self.signature.algorithm().name(),
            kem_implementation: self.kem.version(),
            signature_implementation: self.signature.version(),
            kem_nist_level: self.kem.claimed_nist_level(),
            signature_nist_level: self.signature.claimed_nist_level(),
        }
    }

    /// Generates an ephemeral ML-KEM-768 key pair.
    pub fn generate_kem_keypair(&self) -> Result<KemKeyPair, CryptoError> {
        let (public_key, secret_key) = self
            .kem
            .keypair()
            .map_err(|error| operation_error("ML-KEM key generation", error))?;
        Ok(KemKeyPair {
            public_key: public_key.as_ref().to_vec(),
            secret_key: SecretBytes::new(secret_key.as_ref().to_vec()),
        })
    }

    /// Encapsulates a fresh shared secret to an ML-KEM-768 public key.
    pub fn encapsulate(&self, public_key: &[u8]) -> Result<KemEncapsulation, CryptoError> {
        let public_key = self
            .kem
            .public_key_from_bytes(public_key)
            .ok_or(CryptoError::InvalidLength("ML-KEM public key"))?;
        let (ciphertext, shared_secret) = self
            .kem
            .encapsulate(public_key)
            .map_err(|error| operation_error("ML-KEM encapsulation", error))?;
        Ok(KemEncapsulation {
            ciphertext: ciphertext.as_ref().to_vec(),
            shared_secret: SecretBytes::new(shared_secret.as_ref().to_vec()),
        })
    }

    /// Decapsulates an ML-KEM-768 ciphertext.
    pub fn decapsulate(
        &self,
        secret_key: &SecretBytes,
        ciphertext: &[u8],
    ) -> Result<SecretBytes, CryptoError> {
        let secret_key = self
            .kem
            .secret_key_from_bytes(secret_key.expose_secret())
            .ok_or(CryptoError::InvalidLength("ML-KEM secret key"))?;
        let ciphertext = self
            .kem
            .ciphertext_from_bytes(ciphertext)
            .ok_or(CryptoError::InvalidLength("ML-KEM ciphertext"))?;
        let shared_secret = self
            .kem
            .decapsulate(secret_key, ciphertext)
            .map_err(|error| operation_error("ML-KEM decapsulation", error))?;
        Ok(SecretBytes::new(shared_secret.as_ref().to_vec()))
    }

    /// Generates a long-term ML-DSA-65 signing key pair.
    pub fn generate_signature_keypair(&self) -> Result<SignatureKeyPair, CryptoError> {
        let (public_key, secret_key) = self
            .signature
            .keypair()
            .map_err(|error| operation_error("ML-DSA key generation", error))?;
        Ok(SignatureKeyPair {
            public_key: public_key.as_ref().to_vec(),
            secret_key: SecretBytes::new(secret_key.as_ref().to_vec()),
        })
    }

    /// Signs a bounded, already domain-separated protocol message with ML-DSA-65.
    pub fn sign(&self, secret_key: &SecretBytes, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        validate_message(message)?;
        let secret_key = self
            .signature
            .secret_key_from_bytes(secret_key.expose_secret())
            .ok_or(CryptoError::InvalidLength("ML-DSA secret key"))?;
        let signature = self
            .signature
            .sign(message, secret_key)
            .map_err(|error| operation_error("ML-DSA signing", error))?;
        Ok(signature.as_ref().to_vec())
    }

    /// Verifies an ML-DSA-65 signature over the exact supplied message.
    pub fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        validate_message(message)?;
        let public_key = self
            .signature
            .public_key_from_bytes(public_key)
            .ok_or(CryptoError::InvalidLength("ML-DSA public key"))?;
        let signature = self
            .signature
            .signature_from_bytes(signature)
            .ok_or(CryptoError::InvalidLength("ML-DSA signature"))?;
        self.signature
            .verify(message, signature, public_key)
            .map_err(|_| CryptoError::VerificationFailed)
    }
}

fn validate_message(message: &[u8]) -> Result<(), CryptoError> {
    if message.is_empty() {
        return Err(CryptoError::EmptyMessage);
    }
    if message.len() > MAX_SIGNED_MESSAGE_BYTES {
        return Err(CryptoError::MessageTooLarge);
    }
    Ok(())
}

fn operation_error(operation: &'static str, error: oqs::Error) -> CryptoError {
    CryptoError::Operation {
        operation,
        detail: format!("{error:?}"),
    }
}

/// Errors returned by the post-quantum provider wrapper.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    /// liboqs or the requested algorithm could not be initialized.
    #[error("post-quantum provider initialization failed: {0}")]
    Initialization(String),
    /// A key, ciphertext, or signature has an unexpected length.
    #[error("invalid byte length for {0}")]
    InvalidLength(&'static str),
    /// A provider property differs from the required profile.
    #[error("unexpected post-quantum provider property: {0}")]
    UnexpectedProviderProperty(&'static str),
    /// A cryptographic provider operation failed.
    #[error("{operation} failed: {detail}")]
    Operation {
        /// Operation being performed.
        operation: &'static str,
        /// Non-secret provider error description.
        detail: String,
    },
    /// Signature verification failed.
    #[error("ML-DSA signature verification failed")]
    VerificationFailed,
    /// The caller attempted to sign or verify an empty message.
    #[error("the signed message must not be empty")]
    EmptyMessage,
    /// The signed message exceeds the protocol bound.
    #[error("the signed message exceeds the protocol bound")]
    MessageTooLarge,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ml_kem_round_trip_agrees() {
        let provider = PqProvider::new().unwrap();
        let keypair = provider.generate_kem_keypair().unwrap();
        let encapsulation = provider.encapsulate(keypair.public_key()).unwrap();
        let decapsulated = provider
            .decapsulate(keypair.secret_key(), encapsulation.ciphertext())
            .unwrap();
        assert_eq!(
            encapsulation.shared_secret().expose_secret(),
            decapsulated.expose_secret()
        );
    }

    #[test]
    fn ml_dsa_round_trip_and_tamper_rejection() {
        let provider = PqProvider::new().unwrap();
        let keypair = provider.generate_signature_keypair().unwrap();
        let message = b"ASTRA-PQ signed transcript";
        let signature = provider.sign(keypair.secret_key(), message).unwrap();
        provider
            .verify(keypair.public_key(), message, &signature)
            .unwrap();
        let mut tampered = message.to_vec();
        tampered[0] ^= 1;
        assert_eq!(
            provider.verify(keypair.public_key(), &tampered, &signature),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn profile_is_ml_kem_768_and_ml_dsa_65() {
        let metadata = PqProvider::new().unwrap().metadata();
        assert_eq!(metadata.kem_algorithm, "ML-KEM-768");
        assert_eq!(metadata.signature_algorithm, "ML-DSA-65");
        assert_eq!(metadata.kem_nist_level, 3);
        assert_eq!(metadata.signature_nist_level, 3);
    }
}
