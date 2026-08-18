//! Authority-side request validation and signed authorization evidence.
//!
//! Authorities evaluate only session-bound DPRF inputs. They never receive the
//! gateway KEM secret or derive the final session key.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use astra_common::{
    CanonicalEncode, Digest32, ProtocolError, SessionContext, authorization_input,
    hash_domain_separated,
};
use astra_dprf::{DprfBackend, DprfError, EvaluationRequest, PartialEvaluation};
use astra_pqcrypto::{CryptoError, PqProvider, SecretBytes};
use std::collections::BTreeSet;
use thiserror::Error;

const EVIDENCE_LABEL: &[u8] = b"ASTRA-PQ-EVIDENCE-v1";
const PARTIAL_LABEL: &[u8] = b"ASTRA-PQ-PARTIAL-v1";

/// Validated input delivered to one authorization authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityRequest {
    /// Complete session context, including the epoch and governance checkpoint.
    pub context: SessionContext,
    /// Hash of the deterministically synthesized authorization policy.
    pub policy_hash: Digest32,
    /// Clause-specific DPRF evaluation request.
    pub evaluation: EvaluationRequest,
}

/// Signed, session-bound evidence returned by one authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedPartialEvidence {
    /// Hash of the policy approved by the authority.
    pub policy_hash: Digest32,
    /// Opaque DPRF partial and its backend robustness proof.
    pub partial: PartialEvaluation,
    /// ML-DSA-65 signature over the evidence commitment.
    pub signature: Vec<u8>,
}

/// Non-secret authority configuration for the active governance state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityConfig {
    /// Stable authority identifier.
    pub authority_id: String,
    /// Current authorization epoch.
    pub active_epoch: u64,
    /// Current proactive DPRF-share version.
    pub share_version: u64,
    /// Locally validated off-path governance checkpoint.
    pub approved_checkpoint: Digest32,
    /// Clause identifiers this authority may evaluate.
    pub allowed_clauses: BTreeSet<String>,
}

/// Stateful authority engine with replay rejection.
pub struct AuthorityEngine<'a, B: DprfBackend> {
    config: AuthorityConfig,
    backend: &'a B,
    share: &'a B::Share,
    provider: &'a PqProvider,
    signing_key: &'a SecretBytes,
    completed_sessions: BTreeSet<String>,
}

impl<'a, B: DprfBackend> AuthorityEngine<'a, B> {
    /// Creates an authority engine around externally managed secret material.
    #[must_use]
    pub fn new(
        config: AuthorityConfig,
        backend: &'a B,
        share: &'a B::Share,
        provider: &'a PqProvider,
        signing_key: &'a SecretBytes,
    ) -> Self {
        Self {
            config,
            backend,
            share,
            provider,
            signing_key,
            completed_sessions: BTreeSet::new(),
        }
    }

    /// Validates, evaluates, and signs one authorization request.
    pub fn authorize(
        &mut self,
        request: &AuthorityRequest,
    ) -> Result<SignedPartialEvidence, AuthorityError> {
        request.context.validate()?;
        request.evaluation.validate()?;

        if request.context.epoch != self.config.active_epoch
            || request.evaluation.epoch != self.config.active_epoch
        {
            return Err(AuthorityError::InactiveEpoch);
        }
        if request.evaluation.share_version != self.config.share_version {
            return Err(AuthorityError::StaleShareVersion);
        }
        if request.context.checkpoint_hash != self.config.approved_checkpoint {
            return Err(AuthorityError::UnapprovedCheckpoint);
        }
        if !self
            .config
            .allowed_clauses
            .contains(&request.evaluation.clause_id)
        {
            return Err(AuthorityError::UnauthorizedClause);
        }

        let expected_input = authorization_input(&request.context, &request.policy_hash)?;
        if request.evaluation.input != expected_input {
            return Err(AuthorityError::AuthorizationInputMismatch);
        }

        let replay_key = format!(
            "{}:{}:{}",
            request.context.session_id,
            request.evaluation.clause_id,
            request.evaluation.share_version
        );
        if self.completed_sessions.contains(&replay_key) {
            return Err(AuthorityError::ReplayDetected);
        }

        let partial = self.backend.partial_evaluate(
            &self.config.authority_id,
            self.share,
            &request.evaluation,
        )?;
        validate_backend_output(&self.config.authority_id, &request.evaluation, &partial)?;

        let message = evidence_message(&request.context, &request.policy_hash, &partial)?;
        let signature = self.provider.sign(self.signing_key, &message)?;
        self.completed_sessions.insert(replay_key);

        Ok(SignedPartialEvidence {
            policy_hash: request.policy_hash,
            partial,
            signature,
        })
    }
}

/// Verifies that evidence is bound to the supplied context and authority key.
pub fn verify_evidence(
    provider: &PqProvider,
    authority_public_key: &[u8],
    context: &SessionContext,
    evidence: &SignedPartialEvidence,
) -> Result<(), AuthorityError> {
    context.validate()?;
    let expected_input = authorization_input(context, &evidence.policy_hash)?;
    if evidence.partial.epoch != context.epoch || evidence.partial.input != expected_input {
        return Err(AuthorityError::AuthorizationInputMismatch);
    }
    let message = evidence_message(context, &evidence.policy_hash, &evidence.partial)?;
    provider.verify(authority_public_key, &message, &evidence.signature)?;
    Ok(())
}

fn validate_backend_output(
    authority_id: &str,
    request: &EvaluationRequest,
    partial: &PartialEvaluation,
) -> Result<(), AuthorityError> {
    if partial.authority_id != authority_id {
        return Err(AuthorityError::BackendOutputMismatch("authority_id"));
    }
    if partial.clause_id != request.clause_id {
        return Err(AuthorityError::BackendOutputMismatch("clause_id"));
    }
    if partial.epoch != request.epoch {
        return Err(AuthorityError::BackendOutputMismatch("epoch"));
    }
    if partial.share_version != request.share_version {
        return Err(AuthorityError::BackendOutputMismatch("share_version"));
    }
    if partial.input != request.input {
        return Err(AuthorityError::BackendOutputMismatch("input"));
    }
    if partial.payload.is_empty() {
        return Err(AuthorityError::BackendOutputMismatch("payload"));
    }
    Ok(())
}

fn evidence_message(
    context: &SessionContext,
    policy_hash: &Digest32,
    partial: &PartialEvaluation,
) -> Result<Vec<u8>, AuthorityError> {
    let encoded_context = context.encode_canonical()?;
    let epoch = partial.epoch.to_be_bytes();
    let share_version = partial.share_version.to_be_bytes();
    let partial_commitment = hash_domain_separated(
        PARTIAL_LABEL,
        &[
            partial.authority_id.as_bytes(),
            partial.clause_id.as_bytes(),
            &epoch,
            &share_version,
            partial.input.as_bytes(),
            &partial.payload,
            &partial.proof,
        ],
    );
    Ok(hash_domain_separated(
        EVIDENCE_LABEL,
        &[
            &encoded_context,
            policy_hash.as_bytes(),
            partial.input.as_bytes(),
            partial_commitment.as_bytes(),
        ],
    )
    .as_bytes()
    .to_vec())
}

/// Fail-closed authority-processing errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthorityError {
    /// Shared protocol validation failed.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    /// The DPRF request or backend operation failed.
    #[error(transparent)]
    Dprf(#[from] DprfError),
    /// Post-quantum signing or verification failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// The request does not use the authority's active epoch.
    #[error("authorization request uses an inactive epoch")]
    InactiveEpoch,
    /// The request does not use the current proactive-share version.
    #[error("authorization request uses a stale share version")]
    StaleShareVersion,
    /// The request refers to an unapproved governance checkpoint.
    #[error("governance checkpoint is not locally approved")]
    UnapprovedCheckpoint,
    /// This authority is not assigned to the requested policy clause.
    #[error("authority is not assigned to the requested clause")]
    UnauthorizedClause,
    /// The request or partial is not bound to the expected session and policy.
    #[error("authorization input does not match the session and policy")]
    AuthorizationInputMismatch,
    /// The same authority already completed this session-clause request.
    #[error("duplicate authorization request detected")]
    ReplayDetected,
    /// The concrete backend returned fields that differ from its request.
    #[error("DPRF backend returned mismatched field: {0}")]
    BackendOutputMismatch(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;
    use astra_common::{Digest32, PROTOCOL_VERSION, RiskClass, Secret32, SessionId};

    struct TestBackend;

    impl DprfBackend for TestBackend {
        type Share = [u8; 32];

        fn backend_id(&self) -> &'static str {
            "test-only"
        }

        fn partial_evaluate(
            &self,
            authority_id: &str,
            share: &Self::Share,
            request: &EvaluationRequest,
        ) -> Result<PartialEvaluation, DprfError> {
            Ok(PartialEvaluation {
                authority_id: authority_id.to_owned(),
                clause_id: request.clause_id.clone(),
                epoch: request.epoch,
                share_version: request.share_version,
                input: request.input,
                payload: hash_domain_separated(b"TEST", &[share, request.input.as_bytes()])
                    .as_bytes()
                    .to_vec(),
                proof: vec![],
            })
        }

        fn combine(
            &self,
            _policy: &astra_dprf::ClausePolicy,
            _request: &EvaluationRequest,
            _partials: &[PartialEvaluation],
        ) -> Result<Secret32, DprfError> {
            Ok(Secret32::from_bytes([7; 32]))
        }
    }

    fn context() -> SessionContext {
        SessionContext {
            protocol_version: PROTOCOL_VERSION,
            session_id: SessionId::from_bytes([1; 32]),
            epoch: 4,
            source_domain: "domain-a".to_owned(),
            destination_domain: "domain-b".to_owned(),
            subject: "operator:17".to_owned(),
            resource: "plc:4".to_owned(),
            action: "read-status".to_owned(),
            risk: RiskClass::R1,
            gateway_transcript_hash: Digest32::from_bytes([2; 32]),
            checkpoint_hash: Digest32::from_bytes([3; 32]),
        }
    }

    fn request() -> AuthorityRequest {
        let context = context();
        let policy_hash = Digest32::from_bytes([9; 32]);
        AuthorityRequest {
            evaluation: EvaluationRequest {
                clause_id: "risk-floor".to_owned(),
                epoch: 4,
                share_version: 2,
                input: authorization_input(&context, &policy_hash).unwrap(),
            },
            context,
            policy_hash,
        }
    }

    #[test]
    fn evidence_verifies_and_replay_is_rejected() {
        let provider = PqProvider::new().unwrap();
        let signing_keys = provider.generate_signature_keypair().unwrap();
        let backend = TestBackend;
        let share = [5; 32];
        let config = AuthorityConfig {
            authority_id: "authority-3".to_owned(),
            active_epoch: 4,
            share_version: 2,
            approved_checkpoint: Digest32::from_bytes([3; 32]),
            allowed_clauses: BTreeSet::from(["risk-floor".to_owned()]),
        };
        let mut engine = AuthorityEngine::new(
            config,
            &backend,
            &share,
            &provider,
            signing_keys.secret_key(),
        );
        let request = request();
        let evidence = engine.authorize(&request).unwrap();
        verify_evidence(
            &provider,
            signing_keys.public_key(),
            &request.context,
            &evidence,
        )
        .unwrap();
        assert_eq!(
            engine.authorize(&request),
            Err(AuthorityError::ReplayDetected)
        );
    }

    #[test]
    fn changed_policy_input_is_rejected_before_evaluation() {
        let provider = PqProvider::new().unwrap();
        let signing_keys = provider.generate_signature_keypair().unwrap();
        let backend = TestBackend;
        let share = [5; 32];
        let config = AuthorityConfig {
            authority_id: "authority-3".to_owned(),
            active_epoch: 4,
            share_version: 2,
            approved_checkpoint: Digest32::from_bytes([3; 32]),
            allowed_clauses: BTreeSet::from(["risk-floor".to_owned()]),
        };
        let mut engine = AuthorityEngine::new(
            config,
            &backend,
            &share,
            &provider,
            signing_keys.secret_key(),
        );
        let mut request = request();
        request.policy_hash = Digest32::from_bytes([8; 32]);
        assert_eq!(
            engine.authorize(&request),
            Err(AuthorityError::AuthorizationInputMismatch)
        );
    }
}
