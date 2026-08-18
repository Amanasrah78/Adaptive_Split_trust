//! ML-KEM-768 and ML-DSA-65 provider for the ASTRA-PQ research prototype.
//!
//! The implementation uses the safe `oqs` wrapper over vendored liboqs. It is
//! intended for experimental evaluation and does not assert production readiness.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use astra_common::{Digest32, Secret32};
use hkdf::Hkdf;
use oqs::{kem, sig};
use sha2::Sha384;
use sha3::{Digest, Sha3_256};
use std::fmt;
use std::sync::Once;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

const MAX_SIGNED_MESSAGE_BYTES: usize = 1_048_576;
const MAX_TRANSCRIPT_BYTES: usize = 1_048_576;
const SESSION_INFO_LABEL: &[u8] = b"ASTRA-PQ-v1/session";
const CONFIRMATION_INFO_LABEL: &[u8] = b"ASTRA-PQ-v1/key-confirmation";
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

    /// Imports a provisioned ML-KEM-768 secret key into zeroizing storage.
    ///
    /// The caller must obtain the bytes through an authenticated provisioning
    /// channel. Invalid lengths are rejected by the configured provider.
    pub fn import_kem_secret_key(&self, mut bytes: Vec<u8>) -> Result<SecretBytes, CryptoError> {
        if self.kem.secret_key_from_bytes(&bytes).is_none() {
            bytes.zeroize();
            return Err(CryptoError::InvalidLength("ML-KEM secret key"));
        }
        Ok(SecretBytes::new(bytes))
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

    /// Imports a provisioned ML-DSA-65 secret key into zeroizing storage.
    ///
    /// The caller must obtain the bytes through an authenticated provisioning
    /// channel. Invalid lengths are rejected by the configured provider.
    pub fn import_signature_secret_key(
        &self,
        mut bytes: Vec<u8>,
    ) -> Result<SecretBytes, CryptoError> {
        if self.signature.secret_key_from_bytes(&bytes).is_none() {
            bytes.zeroize();
            return Err(CryptoError::InvalidLength("ML-DSA secret key"));
        }
        Ok(SecretBytes::new(bytes))
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

/// Derives a 256-bit session key from both ASTRA-PQ cryptographic gates.
///
/// The construction follows the manuscript profile:
/// `IKM = K_kem || Z_s`,
/// `salt = SHA3-256(u_s || SHA3-256(T_s))`, and
/// `info = "ASTRA-PQ-v1/session" || u_s || SHA3-256(T_s)`.
pub fn derive_session_key(
    kem_secret: &SecretBytes,
    authorization_secret: &Secret32,
    authorization_input: &Digest32,
    transcript: &[u8],
) -> Result<Secret32, CryptoError> {
    if kem_secret.is_empty() {
        return Err(CryptoError::InvalidLength("ML-KEM shared secret"));
    }
    if transcript.is_empty() {
        return Err(CryptoError::EmptyTranscript);
    }
    if transcript.len() > MAX_TRANSCRIPT_BYTES {
        return Err(CryptoError::TranscriptTooLarge);
    }

    let transcript_hash = Sha3_256::digest(transcript);
    let mut salt_hasher = Sha3_256::new();
    salt_hasher.update(authorization_input.as_bytes());
    salt_hasher.update(transcript_hash.as_slice());
    let salt = salt_hasher.finalize();

    let mut input_key_material = Vec::with_capacity(kem_secret.len() + 32);
    input_key_material.extend_from_slice(kem_secret.expose_secret());
    input_key_material.extend_from_slice(authorization_secret.expose_secret());

    let hkdf = Hkdf::<Sha384>::new(Some(salt.as_slice()), &input_key_material);
    input_key_material.zeroize();

    let mut info = Vec::with_capacity(SESSION_INFO_LABEL.len() + 64);
    info.extend_from_slice(SESSION_INFO_LABEL);
    info.extend_from_slice(authorization_input.as_bytes());
    info.extend_from_slice(transcript_hash.as_slice());

    let mut session_key = [0_u8; 32];
    hkdf.expand(&info, &mut session_key)
        .map_err(|_| CryptoError::KdfExpansion)?;
    Ok(Secret32::from_bytes(session_key))
}

/// Direction bound to a session-key confirmation tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfirmationRole {
    /// Confirmation generated by the initiating gateway.
    Initiator,
    /// Confirmation generated by the responding gateway.
    Responder,
}

impl ConfirmationRole {
    const fn wire_label(self) -> &'static [u8] {
        match self {
            Self::Initiator => b"initiator",
            Self::Responder => b"responder",
        }
    }
}

/// Derives a public, role-separated confirmation tag for a session key.
///
/// The tag proves possession of the dual-gated session key without exposing
/// that key. It is bound to the authenticated handshake transcript and to the
/// sender role to prevent reflection between protocol directions.
pub fn derive_session_confirmation_tag(
    session_key: &Secret32,
    transcript: &[u8],
    role: ConfirmationRole,
) -> Result<Digest32, CryptoError> {
    if transcript.is_empty() {
        return Err(CryptoError::EmptyTranscript);
    }
    if transcript.len() > MAX_TRANSCRIPT_BYTES {
        return Err(CryptoError::TranscriptTooLarge);
    }

    let transcript_hash = Sha3_256::digest(transcript);
    let hkdf = Hkdf::<Sha384>::new(
        Some(transcript_hash.as_slice()),
        session_key.expose_secret(),
    );
    let mut info = Vec::with_capacity(CONFIRMATION_INFO_LABEL.len() + 48);
    info.extend_from_slice(CONFIRMATION_INFO_LABEL);
    info.extend_from_slice(role.wire_label());
    info.extend_from_slice(transcript_hash.as_slice());

    let mut tag = [0_u8; 32];
    hkdf.expand(&info, &mut tag)
        .map_err(|_| CryptoError::KdfExpansion)?;
    Ok(Digest32::from_bytes(tag))
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
    /// The authenticated gateway transcript is empty.
    #[error("the authenticated gateway transcript must not be empty")]
    EmptyTranscript,
    /// The authenticated gateway transcript exceeds its protocol bound.
    #[error("the authenticated gateway transcript exceeds the protocol bound")]
    TranscriptTooLarge,
    /// HKDF could not produce the requested session-key length.
    #[error("HKDF session-key expansion failed")]
    KdfExpansion,
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
    fn provisioned_kem_secret_key_can_decapsulate() {
        let provider = PqProvider::new().unwrap();
        let keypair = provider.generate_kem_keypair().unwrap();
        let provisioned = keypair.secret_key().expose_secret().to_vec();
        let imported = provider.import_kem_secret_key(provisioned).unwrap();
        let encapsulation = provider.encapsulate(keypair.public_key()).unwrap();
        let decapsulated = provider
            .decapsulate(&imported, encapsulation.ciphertext())
            .unwrap();
        assert_eq!(
            encapsulation.shared_secret().expose_secret(),
            decapsulated.expose_secret()
        );
        assert_eq!(
            provider.import_kem_secret_key(vec![0_u8; 1]).unwrap_err(),
            CryptoError::InvalidLength("ML-KEM secret key")
        );
    }

    #[test]
    fn provisioned_signature_key_can_sign() {
        let provider = PqProvider::new().unwrap();
        let keypair = provider.generate_signature_keypair().unwrap();
        let provisioned = keypair.secret_key().expose_secret().to_vec();
        let imported = provider.import_signature_secret_key(provisioned).unwrap();
        let message = b"ASTRA-PQ provisioned signing-key test";
        let signature = provider.sign(&imported, message).unwrap();
        provider
            .verify(keypair.public_key(), message, &signature)
            .unwrap();
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

    #[test]
    fn dual_gate_session_keys_agree() {
        let provider = PqProvider::new().unwrap();
        let keypair = provider.generate_kem_keypair().unwrap();
        let encapsulation = provider.encapsulate(keypair.public_key()).unwrap();
        let decapsulated = provider
            .decapsulate(keypair.secret_key(), encapsulation.ciphertext())
            .unwrap();
        let authorization_secret = Secret32::from_bytes([5; 32]);
        let authorization_input = Digest32::from_bytes([6; 32]);
        let transcript = b"authenticated ASTRA-PQ pre-handshake transcript";

        let initiator_key = derive_session_key(
            &decapsulated,
            &authorization_secret,
            &authorization_input,
            transcript,
        )
        .unwrap();
        let responder_key = derive_session_key(
            encapsulation.shared_secret(),
            &authorization_secret,
            &authorization_input,
            transcript,
        )
        .unwrap();
        assert_eq!(initiator_key.expose_secret(), responder_key.expose_secret());
    }

    #[test]
    fn confirmation_tags_are_role_and_transcript_bound() {
        let session_key = Secret32::from_bytes([9; 32]);
        let transcript = b"authenticated distributed session transcript";
        let responder =
            derive_session_confirmation_tag(&session_key, transcript, ConfirmationRole::Responder)
                .unwrap();
        let repeated =
            derive_session_confirmation_tag(&session_key, transcript, ConfirmationRole::Responder)
                .unwrap();
        let initiator =
            derive_session_confirmation_tag(&session_key, transcript, ConfirmationRole::Initiator)
                .unwrap();
        let changed_transcript = derive_session_confirmation_tag(
            &session_key,
            b"changed distributed session transcript",
            ConfirmationRole::Responder,
        )
        .unwrap();

        assert_eq!(responder, repeated);
        assert_ne!(responder, initiator);
        assert_ne!(responder, changed_transcript);
        assert_eq!(
            derive_session_confirmation_tag(&session_key, b"", ConfirmationRole::Responder),
            Err(CryptoError::EmptyTranscript)
        );
    }

    #[test]
    fn changing_authorization_secret_changes_session_key() {
        let kem_secret = SecretBytes::new(vec![4; 32]);
        let authorization_input = Digest32::from_bytes([6; 32]);
        let first = derive_session_key(
            &kem_secret,
            &Secret32::from_bytes([5; 32]),
            &authorization_input,
            b"transcript",
        )
        .unwrap();
        let second = derive_session_key(
            &kem_secret,
            &Secret32::from_bytes([7; 32]),
            &authorization_input,
            b"transcript",
        )
        .unwrap();
        assert_ne!(first.expose_secret(), second.expose_secret());
    }
}
