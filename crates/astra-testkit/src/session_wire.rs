//! Signed gateway-to-gateway wire objects for the ASTRA-PQ VM experiment.
//!
//! The transport remains bounded JSON over TCP in an isolated lab. Every
//! security-relevant message is nevertheless domain-separated and signed with
//! ML-DSA-65. The initial signed request is also the transcript consumed by the
//! dual-gate session KDF.

use crate::{SESSION_EPOCH, SESSION_SHARE_VERSION, r3_lab_synthesis};
use anyhow::Context;
use astra_authority::SignedPartialEvidence;
use astra_common::{Digest32, RiskClass, SessionContext, SessionId, hash_domain_separated};
use astra_pqcrypto::{PqProvider, SecretBytes};
use astra_synthesizer::SynthesisResult;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Schema carried by the initiator's signed session request.
pub const SESSION_REQUEST_SCHEMA: &str = "astra-pq-session-request-v1";

/// Schema carried by the responder's signed key-confirmation response.
pub const SESSION_RESPONSE_SCHEMA: &str = "astra-pq-session-response-v1";

/// Schema carried by the initiator's signed key-confirmation finish.
pub const SESSION_FINISH_SCHEMA: &str = "astra-pq-session-finish-v1";

/// Schema carried by the responder's signed completion acknowledgement.
pub const SESSION_COMPLETION_SCHEMA: &str = "astra-pq-session-completion-v1";

/// Maximum encoded size of one signed gateway protocol object.
pub const MAX_GATEWAY_MESSAGE_BYTES: usize = 1_048_576;

const MAX_KEM_CIPHERTEXT_BYTES: usize = 8_192;
const R3_EVIDENCE_ITEMS: usize = 6;
const REQUEST_SIGNATURE_LABEL: &[u8] = b"ASTRA-PQ-v1/session-request-signature";
const RESPONSE_SIGNATURE_LABEL: &[u8] = b"ASTRA-PQ-v1/session-response-signature";
const FINISH_SIGNATURE_LABEL: &[u8] = b"ASTRA-PQ-v1/session-finish-signature";
const COMPLETION_SIGNATURE_LABEL: &[u8] = b"ASTRA-PQ-v1/session-completion-signature";
const REQUEST_TRANSCRIPT_LABEL: &[u8] = b"ASTRA-PQ-v1/authenticated-session-request";
const TRANSCRIPT_HASH_LABEL: &[u8] = b"ASTRA-PQ-v1/session-transcript-hash";

/// Unsigned semantic content of the initiator's session request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionHandshakeRequest {
    /// Wire-object schema identifier.
    pub schema: String,
    /// Authenticated initiating gateway identifier.
    pub initiator_gateway: String,
    /// Intended responding gateway identifier.
    pub responder_gateway: String,
    /// Canonical session context used by every authority.
    pub context: SessionContext,
    /// Canonical four-clause R3 authorization structure.
    pub synthesis: SynthesisResult,
    /// Active exact-coalition LWR share version.
    pub share_version: u64,
    /// ML-KEM-768 ciphertext for Gateway B.
    pub kem_ciphertext: Vec<u8>,
    /// Signed authority partials satisfying all R3 clauses.
    pub evidence: Vec<SignedPartialEvidence>,
}

/// ML-DSA-authenticated session request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedSessionHandshakeRequest {
    /// Semantic request content.
    pub request: SessionHandshakeRequest,
    /// Initiator ML-DSA-65 signature.
    pub signature: Vec<u8>,
}

/// Responder result containing explicit server-side key confirmation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionHandshakeResponse {
    /// Wire-object schema identifier.
    pub schema: String,
    /// Established session identifier.
    pub session_id: SessionId,
    /// Digest of the authenticated request transcript.
    pub request_transcript_hash: Digest32,
    /// Public authorization input used by both gateways.
    pub authorization_input: Digest32,
    /// Selected contributors for every required clause.
    pub contributors: BTreeMap<String, Vec<String>>,
    /// Role-separated responder confirmation tag.
    pub responder_confirmation: Digest32,
}

/// ML-DSA-authenticated responder confirmation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedSessionHandshakeResponse {
    /// Semantic response content.
    pub response: SessionHandshakeResponse,
    /// Responder ML-DSA-65 signature.
    pub signature: Vec<u8>,
}

/// Initiator's explicit proof of the same dual-gated session key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionHandshakeFinish {
    /// Wire-object schema identifier.
    pub schema: String,
    /// Established session identifier.
    pub session_id: SessionId,
    /// Digest of the authenticated request transcript.
    pub request_transcript_hash: Digest32,
    /// Role-separated initiator confirmation tag.
    pub initiator_confirmation: Digest32,
}

/// ML-DSA-authenticated initiator finish.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedSessionHandshakeFinish {
    /// Semantic finish content.
    pub finish: SessionHandshakeFinish,
    /// Initiator ML-DSA-65 signature.
    pub signature: Vec<u8>,
}

/// Responder acknowledgement emitted only after client confirmation succeeds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionHandshakeCompletion {
    /// Wire-object schema identifier.
    pub schema: String,
    /// Established session identifier.
    pub session_id: SessionId,
    /// Digest of the authenticated request transcript.
    pub request_transcript_hash: Digest32,
    /// True only after both role-separated confirmation tags are accepted.
    pub accepted: bool,
}

/// ML-DSA-authenticated completion acknowledgement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedSessionHandshakeCompletion {
    /// Semantic completion content.
    pub completion: SessionHandshakeCompletion,
    /// Responder ML-DSA-65 signature.
    pub signature: Vec<u8>,
}

/// Validates, signs, and wraps an initiator session request.
pub fn sign_session_request(
    provider: &PqProvider,
    signing_key: &SecretBytes,
    request: SessionHandshakeRequest,
) -> anyhow::Result<SignedSessionHandshakeRequest> {
    let transcript = authenticated_request_transcript(&request)?;
    let message = signature_digest(REQUEST_SIGNATURE_LABEL, &transcript);
    let signature = provider
        .sign(signing_key, message.as_bytes())
        .context("sign session request")?;
    Ok(SignedSessionHandshakeRequest { request, signature })
}

/// Verifies an initiator request and returns its authenticated KDF transcript.
pub fn verify_session_request(
    provider: &PqProvider,
    verification_key: &[u8],
    signed: &SignedSessionHandshakeRequest,
) -> anyhow::Result<Vec<u8>> {
    let transcript = authenticated_request_transcript(&signed.request)?;
    let message = signature_digest(REQUEST_SIGNATURE_LABEL, &transcript);
    provider
        .verify(verification_key, message.as_bytes(), &signed.signature)
        .context("verify session request")?;
    Ok(transcript)
}

/// Signs the responder's session-key confirmation response.
pub fn sign_session_response(
    provider: &PqProvider,
    signing_key: &SecretBytes,
    response: SessionHandshakeResponse,
) -> anyhow::Result<SignedSessionHandshakeResponse> {
    anyhow::ensure!(
        response.schema == SESSION_RESPONSE_SCHEMA,
        "session response schema mismatch"
    );
    let encoded = encode_bounded(&response)?;
    let message = signature_digest(RESPONSE_SIGNATURE_LABEL, &encoded);
    let signature = provider
        .sign(signing_key, message.as_bytes())
        .context("sign session response")?;
    Ok(SignedSessionHandshakeResponse {
        response,
        signature,
    })
}

/// Verifies the responder's session-key confirmation response.
pub fn verify_session_response(
    provider: &PqProvider,
    verification_key: &[u8],
    signed: &SignedSessionHandshakeResponse,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        signed.response.schema == SESSION_RESPONSE_SCHEMA,
        "session response schema mismatch"
    );
    let encoded = encode_bounded(&signed.response)?;
    let message = signature_digest(RESPONSE_SIGNATURE_LABEL, &encoded);
    provider
        .verify(verification_key, message.as_bytes(), &signed.signature)
        .context("verify session response")
}

/// Signs the initiator's role-separated key-confirmation finish.
pub fn sign_session_finish(
    provider: &PqProvider,
    signing_key: &SecretBytes,
    finish: SessionHandshakeFinish,
) -> anyhow::Result<SignedSessionHandshakeFinish> {
    anyhow::ensure!(
        finish.schema == SESSION_FINISH_SCHEMA,
        "session finish schema mismatch"
    );
    let encoded = encode_bounded(&finish)?;
    let message = signature_digest(FINISH_SIGNATURE_LABEL, &encoded);
    let signature = provider
        .sign(signing_key, message.as_bytes())
        .context("sign session finish")?;
    Ok(SignedSessionHandshakeFinish { finish, signature })
}

/// Verifies the initiator's role-separated key-confirmation finish.
pub fn verify_session_finish(
    provider: &PqProvider,
    verification_key: &[u8],
    signed: &SignedSessionHandshakeFinish,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        signed.finish.schema == SESSION_FINISH_SCHEMA,
        "session finish schema mismatch"
    );
    let encoded = encode_bounded(&signed.finish)?;
    let message = signature_digest(FINISH_SIGNATURE_LABEL, &encoded);
    provider
        .verify(verification_key, message.as_bytes(), &signed.signature)
        .context("verify session finish")
}

/// Signs the responder's final accepted-session acknowledgement.
pub fn sign_session_completion(
    provider: &PqProvider,
    signing_key: &SecretBytes,
    completion: SessionHandshakeCompletion,
) -> anyhow::Result<SignedSessionHandshakeCompletion> {
    anyhow::ensure!(
        completion.schema == SESSION_COMPLETION_SCHEMA && completion.accepted,
        "invalid session completion"
    );
    let encoded = encode_bounded(&completion)?;
    let message = signature_digest(COMPLETION_SIGNATURE_LABEL, &encoded);
    let signature = provider
        .sign(signing_key, message.as_bytes())
        .context("sign session completion")?;
    Ok(SignedSessionHandshakeCompletion {
        completion,
        signature,
    })
}

/// Verifies the responder's final accepted-session acknowledgement.
pub fn verify_session_completion(
    provider: &PqProvider,
    verification_key: &[u8],
    signed: &SignedSessionHandshakeCompletion,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        signed.completion.schema == SESSION_COMPLETION_SCHEMA && signed.completion.accepted,
        "invalid session completion"
    );
    let encoded = encode_bounded(&signed.completion)?;
    let message = signature_digest(COMPLETION_SIGNATURE_LABEL, &encoded);
    provider
        .verify(verification_key, message.as_bytes(), &signed.signature)
        .context("verify session completion")
}

/// Returns the exact authenticated transcript supplied to the session KDF.
pub fn authenticated_request_transcript(
    request: &SessionHandshakeRequest,
) -> anyhow::Result<Vec<u8>> {
    validate_session_request(request)?;
    let encoded = encode_bounded(request)?;
    let mut transcript = Vec::with_capacity(REQUEST_TRANSCRIPT_LABEL.len() + 8 + encoded.len());
    transcript.extend_from_slice(&(REQUEST_TRANSCRIPT_LABEL.len() as u64).to_be_bytes());
    transcript.extend_from_slice(REQUEST_TRANSCRIPT_LABEL);
    transcript.extend_from_slice(&encoded);
    anyhow::ensure!(
        transcript.len() <= MAX_GATEWAY_MESSAGE_BYTES,
        "authenticated request transcript exceeds protocol bound"
    );
    Ok(transcript)
}

/// Hashes the authenticated request transcript for response correlation.
#[must_use]
pub fn request_transcript_hash(transcript: &[u8]) -> Digest32 {
    hash_domain_separated(TRANSCRIPT_HASH_LABEL, &[transcript])
}

fn validate_session_request(request: &SessionHandshakeRequest) -> anyhow::Result<()> {
    anyhow::ensure!(
        request.schema == SESSION_REQUEST_SCHEMA,
        "session request schema mismatch"
    );
    anyhow::ensure!(
        request.initiator_gateway == "gateway-a" && request.responder_gateway == "gateway-b",
        "session gateway role mismatch"
    );
    request.context.validate()?;
    anyhow::ensure!(
        request.context.epoch == SESSION_EPOCH && request.context.risk == RiskClass::R3,
        "session context differs from the provisioned R3 profile"
    );
    anyhow::ensure!(
        request.share_version == SESSION_SHARE_VERSION,
        "session share version mismatch"
    );
    anyhow::ensure!(
        (1..=MAX_KEM_CIPHERTEXT_BYTES).contains(&request.kem_ciphertext.len()),
        "invalid ML-KEM ciphertext size"
    );
    anyhow::ensure!(
        request.evidence.len() == R3_EVIDENCE_ITEMS,
        "R3 session requires exactly six authority evidence items"
    );
    let expected = r3_lab_synthesis(&request.context)?;
    anyhow::ensure!(
        request.synthesis == expected,
        "session synthesis differs from the canonical R3 policy"
    );
    Ok(())
}

fn encode_bounded<T: Serialize>(value: &T) -> anyhow::Result<Vec<u8>> {
    let encoded = serde_json::to_vec(value).context("encode gateway wire object")?;
    anyhow::ensure!(
        (1..=MAX_GATEWAY_MESSAGE_BYTES).contains(&encoded.len()),
        "gateway wire object exceeds protocol bound"
    );
    Ok(encoded)
}

fn signature_digest(label: &[u8], encoded: &[u8]) -> Digest32 {
    hash_domain_separated(label, &[encoded])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_signature_detects_tampering() {
        let provider = PqProvider::new().unwrap();
        let keypair = provider.generate_signature_keypair().unwrap();
        let response = SessionHandshakeResponse {
            schema: SESSION_RESPONSE_SCHEMA.to_owned(),
            session_id: SessionId::from_bytes([1; 32]),
            request_transcript_hash: Digest32::from_bytes([2; 32]),
            authorization_input: Digest32::from_bytes([3; 32]),
            contributors: BTreeMap::from([("risk-floor".to_owned(), vec!["a1".to_owned()])]),
            responder_confirmation: Digest32::from_bytes([4; 32]),
        };
        let mut signed = sign_session_response(&provider, keypair.secret_key(), response).unwrap();
        verify_session_response(&provider, keypair.public_key(), &signed).unwrap();
        signed.response.responder_confirmation = Digest32::from_bytes([5; 32]);
        assert!(verify_session_response(&provider, keypair.public_key(), &signed).is_err());
    }

    #[test]
    fn completion_must_report_acceptance() {
        let provider = PqProvider::new().unwrap();
        let keypair = provider.generate_signature_keypair().unwrap();
        let completion = SessionHandshakeCompletion {
            schema: SESSION_COMPLETION_SCHEMA.to_owned(),
            session_id: SessionId::from_bytes([1; 32]),
            request_transcript_hash: Digest32::from_bytes([2; 32]),
            accepted: false,
        };
        assert!(sign_session_completion(&provider, keypair.secret_key(), completion).is_err());
    }
}
