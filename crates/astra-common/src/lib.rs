//! Shared protocol types and canonical encodings for ASTRA-PQ.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use minicbor::Encoder;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::fmt;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Current ASTRA-PQ wire-protocol version.
pub const PROTOCOL_VERSION: u16 = 2;

/// Maximum permitted lifetime of a session authorization request.
pub const MAX_SESSION_LIFETIME_SECONDS: u64 = 300;

/// Permitted clock difference between protocol participants.
pub const SESSION_CLOCK_SKEW_SECONDS: u64 = 5;

/// Domain separator for the session authorization input.
pub const AUTH_INPUT_LABEL: &[u8] = b"ASTRA-PQ-AUTH-v1";

/// Domain separator for the synthesized policy hash.
pub const POLICY_HASH_LABEL: &[u8] = b"ASTRA-PQ-PHI-v1";

/// Domain separator for the composed distributed authorization output.
pub const AUTH_OUTPUT_LABEL: &[u8] = b"ASTRA-PQ-Z-v1";

/// A fixed-length SHA3-256 digest.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Digest32([u8; 32]);

impl Digest32 {
    /// Creates a digest from exactly 32 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns true when every byte is zero.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }
}

impl fmt::Display for Digest32 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for Digest32 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Digest32({self})")
    }
}

/// A fixed-length secret that is neither printable nor serializable and is
/// erased when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Secret32([u8; 32]);

impl Secret32 {
    /// Creates protected secret storage from exactly 32 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the secret for an immediate cryptographic operation.
    ///
    /// Callers must not log, serialize, clone, or persist the returned bytes.
    #[must_use]
    pub const fn expose_secret(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Secret32 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret32([REDACTED])")
    }
}

/// A unique 256-bit session identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId([u8; 32]);

impl SessionId {
    /// Creates a session identifier from exactly 32 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns true when every byte is zero.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SessionId({self})")
    }
}

/// A fresh 256-bit nonce associated with one session request.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RequestNonce([u8; 32]);

impl RequestNonce {
    /// Creates a request nonce from exactly 32 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the nonce bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns true when every nonce byte is zero.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }
}

impl fmt::Display for RequestNonce {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for RequestNonce {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "RequestNonce({self})")
    }
}

/// Operation risk classes used by the normative synthesis profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskClass {
    /// Read-only operation with no control effect.
    R0,
    /// Operational read or export.
    R1,
    /// Bounded configuration or write.
    R2,
    /// Safety-relevant actuation.
    R3,
    /// Safety-limit or emergency-policy change.
    R4,
}

impl RiskClass {
    /// Returns the policy floor for the number of independent authorities.
    #[must_use]
    pub const fn minimum_authorities(self) -> u16 {
        match self {
            Self::R0 => 1,
            Self::R1 | Self::R2 => 2,
            Self::R3 | Self::R4 => 3,
        }
    }

    /// Returns the stable wire value used in canonical encodings.
    #[must_use]
    pub const fn wire_value(self) -> u8 {
        match self {
            Self::R0 => 0,
            Self::R1 => 1,
            Self::R2 => 2,
            Self::R3 => 3,
            Self::R4 => 4,
        }
    }
}

/// Canonical context bound to every authorization request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionContext {
    /// Wire-protocol version.
    pub protocol_version: u16,
    /// Globally unique session identifier.
    pub session_id: SessionId,
    /// Active governance epoch.
    pub epoch: u64,
    /// Time at which the session request was created, as Unix seconds.
    pub issued_at_unix: u64,
    /// Time after which the session request must no longer be accepted.
    pub expires_at_unix: u64,
    /// Fresh random value preventing reuse of otherwise identical requests.
    pub request_nonce: RequestNonce,
    /// Source administrative domain.
    pub source_domain: String,
    /// Destination administrative domain that owns the resource.
    pub destination_domain: String,
    /// Canonical subject identifier.
    pub subject: String,
    /// Canonical resource identifier.
    pub resource: String,
    /// Canonical action identifier.
    pub action: String,
    /// Risk class assigned by the governed risk policy.
    pub risk: RiskClass,
    /// Hash of the authenticated gateway pre-handshake transcript.
    pub gateway_transcript_hash: Digest32,
    /// Hash of the validated off-path governance checkpoint.
    pub checkpoint_hash: Digest32,
}

impl SessionContext {
    /// Validates context invariants before encoding or hashing.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.protocol_version));
        }
        if self.session_id.is_zero() {
            return Err(ProtocolError::InvalidField("session_id"));
        }
        if self.epoch == 0 {
            return Err(ProtocolError::InvalidField("epoch"));
        }
        if self.issued_at_unix == 0 {
            return Err(ProtocolError::InvalidField("issued_at_unix"));
        }
        if self.expires_at_unix <= self.issued_at_unix {
            return Err(ProtocolError::InvalidField("expires_at_unix"));
        }
        if self.expires_at_unix - self.issued_at_unix > MAX_SESSION_LIFETIME_SECONDS {
            return Err(ProtocolError::InvalidField("session_lifetime"));
        }
        if self.request_nonce.is_zero() {
            return Err(ProtocolError::InvalidField("request_nonce"));
        }
        validate_identifier("source_domain", &self.source_domain)?;
        validate_identifier("destination_domain", &self.destination_domain)?;
        validate_identifier("subject", &self.subject)?;
        validate_identifier("resource", &self.resource)?;
        validate_identifier("action", &self.action)?;
        if self.source_domain == self.destination_domain {
            return Err(ProtocolError::NotCrossDomain);
        }
        if self.gateway_transcript_hash.is_zero() {
            return Err(ProtocolError::InvalidField("gateway_transcript_hash"));
        }
        if self.checkpoint_hash.is_zero() {
            return Err(ProtocolError::InvalidField("checkpoint_hash"));
        }
        Ok(())
    }

    /// Validates the context and its acceptance interval at `now`.
    pub fn validate_at(&self, now: u64) -> Result<(), ProtocolError> {
        self.validate()?;
        if now.saturating_add(SESSION_CLOCK_SKEW_SECONDS) < self.issued_at_unix {
            return Err(ProtocolError::SessionNotYetValid);
        }
        if now
            > self
                .expires_at_unix
                .saturating_add(SESSION_CLOCK_SKEW_SECONDS)
        {
            return Err(ProtocolError::SessionExpired);
        }
        Ok(())
    }
}

/// Trait for byte-exact canonical protocol encoding.
pub trait CanonicalEncode {
    /// Encodes a value using the versioned canonical representation.
    fn encode_canonical(&self) -> Result<Vec<u8>, ProtocolError>;
}

impl CanonicalEncode for SessionContext {
    fn encode_canonical(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let mut bytes = Vec::new();
        let mut encoder = Encoder::new(&mut bytes);

        macro_rules! encode {
            ($operation:expr) => {
                $operation.map_err(|error| ProtocolError::Encoding(error.to_string()))?;
            };
        }

        // Integer keys are emitted in ascending order and all lengths are definite.
        encode!(encoder.map(14));
        encode!(encoder.u8(0));
        encode!(encoder.u16(self.protocol_version));
        encode!(encoder.u8(1));
        encode!(encoder.bytes(self.session_id.as_bytes()));
        encode!(encoder.u8(2));
        encode!(encoder.u64(self.epoch));
        encode!(encoder.u8(3));
        encode!(encoder.str(&self.source_domain));
        encode!(encoder.u8(4));
        encode!(encoder.str(&self.destination_domain));
        encode!(encoder.u8(5));
        encode!(encoder.str(&self.subject));
        encode!(encoder.u8(6));
        encode!(encoder.str(&self.resource));
        encode!(encoder.u8(7));
        encode!(encoder.str(&self.action));
        encode!(encoder.u8(8));
        encode!(encoder.u8(self.risk.wire_value()));
        encode!(encoder.u8(9));
        encode!(encoder.bytes(self.gateway_transcript_hash.as_bytes()));
        encode!(encoder.u8(10));
        encode!(encoder.bytes(self.checkpoint_hash.as_bytes()));
        encode!(encoder.u8(11));
        encode!(encoder.u64(self.issued_at_unix));
        encode!(encoder.u8(12));
        encode!(encoder.u64(self.expires_at_unix));
        encode!(encoder.u8(13));
        encode!(encoder.bytes(self.request_nonce.as_bytes()));

        Ok(bytes)
    }
}

/// Hashes length-prefixed parts under an explicit protocol domain separator.
#[must_use]
pub fn hash_domain_separated(label: &[u8], parts: &[&[u8]]) -> Digest32 {
    let mut hasher = Sha3_256::new();
    hasher.update((label.len() as u64).to_be_bytes());
    hasher.update(label);
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    Digest32::from_bytes(hasher.finalize().into())
}

/// Constructs the session-bound DPRF input shared by all selected clauses.
pub fn authorization_input(
    context: &SessionContext,
    policy_hash: &Digest32,
) -> Result<Digest32, ProtocolError> {
    let encoded_context = context.encode_canonical()?;
    Ok(hash_domain_separated(
        AUTH_INPUT_LABEL,
        &[encoded_context.as_slice(), policy_hash.as_bytes()],
    ))
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), ProtocolError> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(ProtocolError::InvalidField(field));
    }
    Ok(())
}

/// Errors produced while validating or encoding protocol objects.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    /// The received wire-protocol version is unsupported.
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u16),
    /// A required field is empty, malformed, or outside its bound.
    #[error("invalid protocol field: {0}")]
    InvalidField(&'static str),
    /// The source and destination domains are identical.
    #[error("the session is not cross-domain")]
    NotCrossDomain,
    /// The request was received before its acceptance interval.
    #[error("the session request is not yet valid")]
    SessionNotYetValid,
    /// The request was received after its acceptance interval.
    #[error("the session request has expired")]
    SessionExpired,
    /// Canonical CBOR encoding failed.
    #[error("canonical encoding failed: {0}")]
    Encoding(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn context(epoch: u64) -> SessionContext {
        SessionContext {
            protocol_version: PROTOCOL_VERSION,
            session_id: SessionId::from_bytes([1; 32]),
            epoch,
            issued_at_unix: 100,
            expires_at_unix: 200,
            request_nonce: RequestNonce::from_bytes([4; 32]),
            source_domain: "domain-a".to_owned(),
            destination_domain: "domain-b".to_owned(),
            subject: "operator:17".to_owned(),
            resource: "plc:4".to_owned(),
            action: "read-status".to_owned(),
            risk: RiskClass::R0,
            gateway_transcript_hash: Digest32::from_bytes([2; 32]),
            checkpoint_hash: Digest32::from_bytes([3; 32]),
        }
    }

    #[test]
    fn canonical_encoding_is_deterministic() {
        let first = context(7).encode_canonical().unwrap();
        let second = context(7).encode_canonical().unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn destination_must_differ_from_source() {
        let mut invalid = context(7);
        invalid.destination_domain = invalid.source_domain.clone();
        assert_eq!(invalid.validate(), Err(ProtocolError::NotCrossDomain));
    }

    #[test]
    fn invalid_session_intervals_are_rejected() {
        let mut invalid = context(7);
        invalid.issued_at_unix = 0;
        assert_eq!(
            invalid.validate(),
            Err(ProtocolError::InvalidField("issued_at_unix"))
        );

        let mut invalid = context(7);
        invalid.expires_at_unix = invalid.issued_at_unix;
        assert_eq!(
            invalid.validate(),
            Err(ProtocolError::InvalidField("expires_at_unix"))
        );

        let mut invalid = context(7);
        invalid.expires_at_unix = invalid.issued_at_unix + MAX_SESSION_LIFETIME_SECONDS + 1;
        assert_eq!(
            invalid.validate(),
            Err(ProtocolError::InvalidField("session_lifetime"))
        );
    }

    #[test]
    fn zero_request_nonce_is_rejected() {
        let mut invalid = context(7);
        invalid.request_nonce = RequestNonce::from_bytes([0; 32]);
        assert_eq!(
            invalid.validate(),
            Err(ProtocolError::InvalidField("request_nonce"))
        );
    }

    #[test]
    fn request_interval_allows_only_bounded_clock_skew() {
        let valid = context(7);

        assert_eq!(
            valid.validate_at(94),
            Err(ProtocolError::SessionNotYetValid)
        );
        assert!(valid.validate_at(95).is_ok());
        assert!(valid.validate_at(205).is_ok());
        assert_eq!(valid.validate_at(206), Err(ProtocolError::SessionExpired));
    }

    #[test]
    fn validity_fields_change_authorization_input() {
        let policy_hash = Digest32::from_bytes([9; 32]);
        let base = context(7);

        let mut changed_issue_time = base.clone();
        changed_issue_time.issued_at_unix += 1;

        let mut changed_expiry = base.clone();
        changed_expiry.expires_at_unix += 1;

        let mut changed_nonce = base.clone();
        changed_nonce.request_nonce = RequestNonce::from_bytes([5; 32]);

        let base_input = authorization_input(&base, &policy_hash).unwrap();

        assert_ne!(
            base_input,
            authorization_input(&changed_issue_time, &policy_hash).unwrap()
        );
        assert_ne!(
            base_input,
            authorization_input(&changed_expiry, &policy_hash).unwrap()
        );
        assert_ne!(
            base_input,
            authorization_input(&changed_nonce, &policy_hash).unwrap()
        );
    }

    #[test]
    fn risk_floors_match_the_normative_profile() {
        assert_eq!(RiskClass::R0.minimum_authorities(), 1);
        assert_eq!(RiskClass::R1.minimum_authorities(), 2);
        assert_eq!(RiskClass::R2.minimum_authorities(), 2);
        assert_eq!(RiskClass::R3.minimum_authorities(), 3);
        assert_eq!(RiskClass::R4.minimum_authorities(), 3);
    }

    proptest! {
        #[test]
        fn changing_epoch_changes_authorization_input(first in 1_u64..u64::MAX, second in 1_u64..u64::MAX) {
            prop_assume!(first != second);
            let policy_hash = Digest32::from_bytes([9; 32]);
            let first_input = authorization_input(&context(first), &policy_hash).unwrap();
            let second_input = authorization_input(&context(second), &policy_hash).unwrap();
            prop_assert_ne!(first_input, second_input);
        }
    }
}
