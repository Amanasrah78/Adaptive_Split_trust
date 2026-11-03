//! Authenticated application-record protection for established ASTRA-PQ sessions.
//!
//! Each traffic direction uses an independently derived AES-256-GCM key and
//! 96-bit base IV. Record sequence numbers are strictly monotonic.
//!
//! The AEAD nonce is:
//!
//! `nonce_j = base_iv XOR pad96(sequence_number)`
//!
//! Associated data binds the record header and authenticated handshake
//! transcript hash.

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use astra_common::{Digest32, Secret32, SessionId};
use thiserror::Error;

/// Record-layer format version.
pub const RECORD_VERSION: u16 = 1;

/// Maximum plaintext carried by one protected record.
pub const MAX_RECORD_PLAINTEXT_BYTES: usize = 1_048_512;

/// Encoded fixed record-header length.
pub const RECORD_HEADER_BYTES: usize = 48;

/// AES-GCM authentication-tag length.
pub const RECORD_TAG_BYTES: usize = 16;

/// AES-GCM nonce length.
pub const RECORD_NONCE_BYTES: usize = 12;

const RECORD_AAD_LABEL: &[u8] = b"ASTRA-PQ-v1/record-aad";

/// Protected-record traffic direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordDirection {
    /// Initiating gateway to responding gateway.
    InitiatorToResponder = 1,

    /// Responding gateway to initiating gateway.
    ResponderToInitiator = 2,
}

impl RecordDirection {
    fn decode(value: u8) -> Result<Self, RecordError> {
        match value {
            1 => Ok(Self::InitiatorToResponder),
            2 => Ok(Self::ResponderToInitiator),
            _ => Err(RecordError::InvalidDirection),
        }
    }
}

/// Semantic content carried by a protected record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordContentType {
    /// Generic protected application data.
    ApplicationData = 1,
}

impl RecordContentType {
    fn decode(value: u8) -> Result<Self, RecordError> {
        match value {
            1 => Ok(Self::ApplicationData),
            _ => Err(RecordError::InvalidContentType),
        }
    }
}

/// Authenticated fixed record header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordHeader {
    /// Record-layer format version.
    pub version: u16,

    /// Established session identifier.
    pub session_id: SessionId,

    /// Traffic direction.
    pub direction: RecordDirection,

    /// Semantic record content type.
    pub content_type: RecordContentType,

    /// Strictly monotonic per-direction sequence number.
    pub sequence_number: u64,

    /// Plaintext length before AEAD protection.
    pub plaintext_length: u32,
}

impl RecordHeader {
    /// Encodes the fixed record header canonically.
    #[must_use]
    pub fn encode(&self) -> [u8; RECORD_HEADER_BYTES] {
        let mut encoded = [0_u8; RECORD_HEADER_BYTES];

        encoded[0..2].copy_from_slice(&self.version.to_be_bytes());
        encoded[2..34].copy_from_slice(self.session_id.as_bytes());
        encoded[34] = self.direction as u8;
        encoded[35] = self.content_type as u8;
        encoded[36..44].copy_from_slice(&self.sequence_number.to_be_bytes());
        encoded[44..48].copy_from_slice(&self.plaintext_length.to_be_bytes());

        encoded
    }

    /// Decodes and structurally validates a fixed record header.
    pub fn decode(encoded: &[u8]) -> Result<Self, RecordError> {
        if encoded.len() != RECORD_HEADER_BYTES {
            return Err(RecordError::InvalidHeaderLength);
        }

        let version = u16::from_be_bytes([encoded[0], encoded[1]]);
        if version != RECORD_VERSION {
            return Err(RecordError::UnsupportedVersion(version));
        }

        let mut session_id = [0_u8; 32];
        session_id.copy_from_slice(&encoded[2..34]);

        let direction = RecordDirection::decode(encoded[34])?;
        let content_type = RecordContentType::decode(encoded[35])?;

        let sequence_number = u64::from_be_bytes(
            encoded[36..44]
                .try_into()
                .map_err(|_| RecordError::InvalidHeaderLength)?,
        );

        let plaintext_length = u32::from_be_bytes(
            encoded[44..48]
                .try_into()
                .map_err(|_| RecordError::InvalidHeaderLength)?,
        );

        if usize::try_from(plaintext_length).map_err(|_| RecordError::RecordTooLarge)?
            > MAX_RECORD_PLAINTEXT_BYTES
        {
            return Err(RecordError::RecordTooLarge);
        }

        Ok(Self {
            version,
            session_id: SessionId::from_bytes(session_id),
            direction,
            content_type,
            sequence_number,
            plaintext_length,
        })
    }
}

/// Stateful sender for one protected traffic direction.
pub struct RecordSender<'a> {
    key: &'a Secret32,
    base_iv: &'a [u8; RECORD_NONCE_BYTES],
    session_id: SessionId,
    direction: RecordDirection,
    transcript_hash: Digest32,
    next_sequence: u64,
    exhausted: bool,
}

impl<'a> RecordSender<'a> {
    /// Creates a new sender beginning at sequence number zero.
    #[must_use]
    pub fn new(
        key: &'a Secret32,
        base_iv: &'a [u8; RECORD_NONCE_BYTES],
        session_id: SessionId,
        direction: RecordDirection,
        transcript_hash: Digest32,
    ) -> Self {
        Self {
            key,
            base_iv,
            session_id,
            direction,
            transcript_hash,
            next_sequence: 0,
            exhausted: false,
        }
    }

    /// Protects one plaintext record and advances the sequence only on success.
    pub fn seal(
        &mut self,
        content_type: RecordContentType,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, RecordError> {
        if self.exhausted {
            return Err(RecordError::SequenceExhausted);
        }

        if plaintext.is_empty() {
            return Err(RecordError::EmptyPlaintext);
        }

        if plaintext.len() > MAX_RECORD_PLAINTEXT_BYTES {
            return Err(RecordError::RecordTooLarge);
        }

        let plaintext_length =
            u32::try_from(plaintext.len()).map_err(|_| RecordError::RecordTooLarge)?;

        let sequence_number = self.next_sequence;

        let header = RecordHeader {
            version: RECORD_VERSION,
            session_id: self.session_id,
            direction: self.direction,
            content_type,
            sequence_number,
            plaintext_length,
        };

        let encoded_header = header.encode();
        let nonce_bytes = derive_nonce(self.base_iv, sequence_number);
        let aad = record_aad(&encoded_header, &self.transcript_hash);

        let cipher = Aes256Gcm::new_from_slice(self.key.expose_secret())
            .map_err(|_| RecordError::InvalidKey)?;

        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| RecordError::AuthenticationFailed)?;

        let mut record = Vec::with_capacity(RECORD_HEADER_BYTES + ciphertext.len());
        record.extend_from_slice(&encoded_header);
        record.extend_from_slice(&ciphertext);

        if sequence_number == u64::MAX {
            self.exhausted = true;
        } else {
            self.next_sequence += 1;
        }

        Ok(record)
    }
}

/// Stateful receiver for one protected traffic direction.
pub struct RecordReceiver<'a> {
    key: &'a Secret32,
    base_iv: &'a [u8; RECORD_NONCE_BYTES],
    session_id: SessionId,
    direction: RecordDirection,
    transcript_hash: Digest32,
    next_sequence: u64,
    exhausted: bool,
}

impl<'a> RecordReceiver<'a> {
    /// Creates a new receiver expecting sequence number zero.
    #[must_use]
    pub fn new(
        key: &'a Secret32,
        base_iv: &'a [u8; RECORD_NONCE_BYTES],
        session_id: SessionId,
        direction: RecordDirection,
        transcript_hash: Digest32,
    ) -> Self {
        Self {
            key,
            base_iv,
            session_id,
            direction,
            transcript_hash,
            next_sequence: 0,
            exhausted: false,
        }
    }

    /// Authenticates and decrypts exactly the next expected record.
    ///
    /// The expected sequence is advanced only after successful AEAD
    /// authentication.
    pub fn open(
        &mut self,
        encoded_record: &[u8],
    ) -> Result<(RecordContentType, Vec<u8>), RecordError> {
        if self.exhausted {
            return Err(RecordError::SequenceExhausted);
        }

        if encoded_record.len() < RECORD_HEADER_BYTES + RECORD_TAG_BYTES {
            return Err(RecordError::TruncatedRecord);
        }

        let encoded_header = &encoded_record[..RECORD_HEADER_BYTES];
        let header = RecordHeader::decode(encoded_header)?;

        if header.session_id != self.session_id {
            return Err(RecordError::WrongSession);
        }

        if header.direction != self.direction {
            return Err(RecordError::WrongDirection);
        }

        if header.sequence_number != self.next_sequence {
            return Err(RecordError::UnexpectedSequence {
                expected: self.next_sequence,
                received: header.sequence_number,
            });
        }

        let plaintext_length =
            usize::try_from(header.plaintext_length).map_err(|_| RecordError::RecordTooLarge)?;

        let expected_ciphertext_length = plaintext_length
            .checked_add(RECORD_TAG_BYTES)
            .ok_or(RecordError::RecordTooLarge)?;

        let ciphertext = &encoded_record[RECORD_HEADER_BYTES..];

        if ciphertext.len() != expected_ciphertext_length {
            return Err(RecordError::LengthMismatch);
        }

        let nonce_bytes = derive_nonce(self.base_iv, header.sequence_number);
        let aad = record_aad(encoded_header, &self.transcript_hash);

        let cipher = Aes256Gcm::new_from_slice(self.key.expose_secret())
            .map_err(|_| RecordError::InvalidKey)?;

        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| RecordError::AuthenticationFailed)?;

        if plaintext.len() != plaintext_length {
            return Err(RecordError::LengthMismatch);
        }

        if header.sequence_number == u64::MAX {
            self.exhausted = true;
        } else {
            self.next_sequence += 1;
        }

        Ok((header.content_type, plaintext))
    }
}

fn derive_nonce(
    base_iv: &[u8; RECORD_NONCE_BYTES],
    sequence_number: u64,
) -> [u8; RECORD_NONCE_BYTES] {
    let mut nonce = *base_iv;
    let encoded_sequence = sequence_number.to_be_bytes();

    for (target, sequence_byte) in nonce[4..].iter_mut().zip(encoded_sequence) {
        *target ^= sequence_byte;
    }

    nonce
}

fn record_aad(encoded_header: &[u8], transcript_hash: &Digest32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(RECORD_AAD_LABEL.len() + encoded_header.len() + 32);

    aad.extend_from_slice(RECORD_AAD_LABEL);
    aad.extend_from_slice(encoded_header);
    aad.extend_from_slice(transcript_hash.as_bytes());

    aad
}

/// Fail-closed record-layer error.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RecordError {
    /// AES-256-GCM rejected the supplied traffic key.
    #[error("invalid AES-256-GCM traffic key")]
    InvalidKey,

    /// Record header had an unexpected byte length.
    #[error("invalid protected-record header length")]
    InvalidHeaderLength,

    /// Record-layer format version is unsupported.
    #[error("unsupported protected-record version {0}")]
    UnsupportedVersion(u16),

    /// Encoded record direction is unknown.
    #[error("invalid protected-record direction")]
    InvalidDirection,

    /// Encoded content type is unknown.
    #[error("invalid protected-record content type")]
    InvalidContentType,

    /// Protected record belongs to a different session.
    #[error("protected record belongs to another session")]
    WrongSession,

    /// Protected record was received on the wrong traffic direction.
    #[error("protected record has the wrong traffic direction")]
    WrongDirection,

    /// Record sequence did not match the exact next expected sequence.
    #[error("unexpected protected-record sequence: expected {expected}, received {received}")]
    UnexpectedSequence {
        /// Next sequence required by the receiver.
        expected: u64,

        /// Sequence encoded by the received record.
        received: u64,
    },

    /// Per-direction sequence space has been exhausted.
    #[error("protected-record sequence space exhausted")]
    SequenceExhausted,

    /// Zero-length application records are not accepted.
    #[error("protected-record plaintext must not be empty")]
    EmptyPlaintext,

    /// Plaintext exceeds the protocol bound.
    #[error("protected-record plaintext exceeds protocol bound")]
    RecordTooLarge,

    /// Encoded record is shorter than a header and AEAD tag.
    #[error("truncated protected record")]
    TruncatedRecord,

    /// Header plaintext length and encrypted payload length disagree.
    #[error("protected-record length mismatch")]
    LengthMismatch,

    /// AES-GCM authentication failed.
    #[error("protected-record authentication failed")]
    AuthenticationFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(value: u8) -> Secret32 {
        Secret32::from_bytes([value; 32])
    }

    fn session(value: u8) -> SessionId {
        SessionId::from_bytes([value; 32])
    }

    fn transcript(value: u8) -> Digest32 {
        Digest32::from_bytes([value; 32])
    }

    #[test]
    fn protected_record_round_trip_succeeds() {
        let key = key(1);
        let iv = [2_u8; RECORD_NONCE_BYTES];
        let sid = session(3);
        let transcript = transcript(4);

        let mut sender = RecordSender::new(
            &key,
            &iv,
            sid,
            RecordDirection::InitiatorToResponder,
            transcript,
        );

        let mut receiver = RecordReceiver::new(
            &key,
            &iv,
            sid,
            RecordDirection::InitiatorToResponder,
            transcript,
        );

        let encoded = sender
            .seal(RecordContentType::ApplicationData, b"protected payload")
            .unwrap();

        let (content_type, plaintext) = receiver.open(&encoded).unwrap();

        assert_eq!(content_type, RecordContentType::ApplicationData);
        assert_eq!(plaintext, b"protected payload");
    }

    #[test]
    fn replayed_record_is_rejected() {
        let key = key(5);
        let iv = [6_u8; RECORD_NONCE_BYTES];
        let sid = session(7);
        let transcript = transcript(8);

        let mut sender = RecordSender::new(
            &key,
            &iv,
            sid,
            RecordDirection::InitiatorToResponder,
            transcript,
        );

        let mut receiver = RecordReceiver::new(
            &key,
            &iv,
            sid,
            RecordDirection::InitiatorToResponder,
            transcript,
        );

        let encoded = sender
            .seal(RecordContentType::ApplicationData, b"once")
            .unwrap();

        receiver.open(&encoded).unwrap();

        assert_eq!(
            receiver.open(&encoded),
            Err(RecordError::UnexpectedSequence {
                expected: 1,
                received: 0,
            })
        );
    }

    #[test]
    fn out_of_order_record_is_rejected() {
        let key = key(9);
        let iv = [10_u8; RECORD_NONCE_BYTES];
        let sid = session(11);
        let transcript = transcript(12);

        let mut sender = RecordSender::new(
            &key,
            &iv,
            sid,
            RecordDirection::InitiatorToResponder,
            transcript,
        );

        let first = sender
            .seal(RecordContentType::ApplicationData, b"first")
            .unwrap();

        let second = sender
            .seal(RecordContentType::ApplicationData, b"second")
            .unwrap();

        let mut receiver = RecordReceiver::new(
            &key,
            &iv,
            sid,
            RecordDirection::InitiatorToResponder,
            transcript,
        );

        assert_eq!(
            receiver.open(&second),
            Err(RecordError::UnexpectedSequence {
                expected: 0,
                received: 1,
            })
        );

        receiver.open(&first).unwrap();
        receiver.open(&second).unwrap();
    }

    #[test]
    fn wrong_direction_is_rejected() {
        let key = key(13);
        let iv = [14_u8; RECORD_NONCE_BYTES];
        let sid = session(15);
        let transcript = transcript(16);

        let mut sender = RecordSender::new(
            &key,
            &iv,
            sid,
            RecordDirection::InitiatorToResponder,
            transcript,
        );

        let encoded = sender
            .seal(RecordContentType::ApplicationData, b"direction")
            .unwrap();

        let mut receiver = RecordReceiver::new(
            &key,
            &iv,
            sid,
            RecordDirection::ResponderToInitiator,
            transcript,
        );

        assert_eq!(receiver.open(&encoded), Err(RecordError::WrongDirection));
    }

    #[test]
    fn wrong_session_is_rejected() {
        let key = key(17);
        let iv = [18_u8; RECORD_NONCE_BYTES];
        let transcript = transcript(19);

        let mut sender = RecordSender::new(
            &key,
            &iv,
            session(20),
            RecordDirection::InitiatorToResponder,
            transcript,
        );

        let encoded = sender
            .seal(RecordContentType::ApplicationData, b"session")
            .unwrap();

        let mut receiver = RecordReceiver::new(
            &key,
            &iv,
            session(21),
            RecordDirection::InitiatorToResponder,
            transcript,
        );

        assert_eq!(receiver.open(&encoded), Err(RecordError::WrongSession));
    }

    #[test]
    fn ciphertext_tampering_is_rejected() {
        let key = key(22);
        let iv = [23_u8; RECORD_NONCE_BYTES];
        let sid = session(24);
        let transcript = transcript(25);

        let mut sender = RecordSender::new(
            &key,
            &iv,
            sid,
            RecordDirection::InitiatorToResponder,
            transcript,
        );

        let mut encoded = sender
            .seal(RecordContentType::ApplicationData, b"authenticated")
            .unwrap();

        let final_byte = encoded.len() - 1;
        encoded[final_byte] ^= 1;

        let mut receiver = RecordReceiver::new(
            &key,
            &iv,
            sid,
            RecordDirection::InitiatorToResponder,
            transcript,
        );

        assert_eq!(
            receiver.open(&encoded),
            Err(RecordError::AuthenticationFailed)
        );
    }

    #[test]
    fn authenticated_header_tampering_is_rejected() {
        let key = key(26);
        let iv = [27_u8; RECORD_NONCE_BYTES];
        let sid = session(28);
        let transcript = transcript(29);

        let mut sender = RecordSender::new(
            &key,
            &iv,
            sid,
            RecordDirection::InitiatorToResponder,
            transcript,
        );

        let mut encoded = sender
            .seal(RecordContentType::ApplicationData, b"header")
            .unwrap();

        // Change content type to another syntactically invalid value.
        encoded[35] = 2;

        let mut receiver = RecordReceiver::new(
            &key,
            &iv,
            sid,
            RecordDirection::InitiatorToResponder,
            transcript,
        );

        assert_eq!(
            receiver.open(&encoded),
            Err(RecordError::InvalidContentType)
        );
    }

    #[test]
    fn transcript_mismatch_fails_authentication() {
        let key = key(30);
        let iv = [31_u8; RECORD_NONCE_BYTES];
        let sid = session(32);

        let mut sender = RecordSender::new(
            &key,
            &iv,
            sid,
            RecordDirection::InitiatorToResponder,
            transcript(33),
        );

        let encoded = sender
            .seal(RecordContentType::ApplicationData, b"transcript-bound")
            .unwrap();

        let mut receiver = RecordReceiver::new(
            &key,
            &iv,
            sid,
            RecordDirection::InitiatorToResponder,
            transcript(34),
        );

        assert_eq!(
            receiver.open(&encoded),
            Err(RecordError::AuthenticationFailed)
        );
    }

    #[test]
    fn oversized_plaintext_is_rejected_before_encryption() {
        let key = key(35);
        let iv = [36_u8; RECORD_NONCE_BYTES];

        let mut sender = RecordSender::new(
            &key,
            &iv,
            session(37),
            RecordDirection::InitiatorToResponder,
            transcript(38),
        );

        let oversized = vec![0_u8; MAX_RECORD_PLAINTEXT_BYTES + 1];

        assert_eq!(
            sender.seal(RecordContentType::ApplicationData, &oversized),
            Err(RecordError::RecordTooLarge)
        );
    }

    #[test]
    fn failed_authentication_does_not_advance_receiver_sequence() {
        let key = key(39);
        let iv = [40_u8; RECORD_NONCE_BYTES];
        let sid = session(41);
        let transcript = transcript(42);

        let mut sender = RecordSender::new(
            &key,
            &iv,
            sid,
            RecordDirection::InitiatorToResponder,
            transcript,
        );

        let valid = sender
            .seal(RecordContentType::ApplicationData, b"retry-valid")
            .unwrap();

        let mut damaged = valid.clone();
        let final_byte = damaged.len() - 1;
        damaged[final_byte] ^= 1;

        let mut receiver = RecordReceiver::new(
            &key,
            &iv,
            sid,
            RecordDirection::InitiatorToResponder,
            transcript,
        );

        assert_eq!(
            receiver.open(&damaged),
            Err(RecordError::AuthenticationFailed)
        );

        // Sequence 0 must still be expected after failed authentication.
        assert!(receiver.open(&valid).is_ok());
    }

    #[test]
    fn sequence_exhaustion_fails_closed() {
        let key = key(43);
        let iv = [44_u8; RECORD_NONCE_BYTES];

        let mut sender = RecordSender::new(
            &key,
            &iv,
            session(45),
            RecordDirection::InitiatorToResponder,
            transcript(46),
        );

        sender.next_sequence = u64::MAX;

        let final_record = sender
            .seal(RecordContentType::ApplicationData, b"final")
            .unwrap();

        assert_eq!(
            sender.seal(RecordContentType::ApplicationData, b"too-late"),
            Err(RecordError::SequenceExhausted)
        );

        let mut receiver = RecordReceiver::new(
            &key,
            &iv,
            session(45),
            RecordDirection::InitiatorToResponder,
            transcript(46),
        );

        receiver.next_sequence = u64::MAX;

        assert!(receiver.open(&final_record).is_ok());

        assert_eq!(
            receiver.open(&final_record),
            Err(RecordError::SequenceExhausted)
        );
    }
}
