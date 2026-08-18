//! Gateway-side authorization aggregation and dual-gate key establishment.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use astra_authority::{AuthorityError, SignedPartialEvidence, verify_evidence};
use astra_common::{
    AUTH_OUTPUT_LABEL, CanonicalEncode, Digest32, POLICY_HASH_LABEL, ProtocolError, Secret32,
    SessionContext, authorization_input, hash_domain_separated,
};
use astra_dprf::{
    ClausePolicy, DprfBackend, DprfError, EvaluationRequest, PartialEvaluation, validate_and_select,
};
use astra_governance::{
    GovernanceCheckpoint, GovernanceError, LocalGovernanceState, checkpoint_hash,
    checkpoint_is_fresh,
};
use astra_pqcrypto::{CryptoError, PqProvider, SecretBytes, derive_session_key};
use astra_synthesizer::{AuthorizationStructure, DistinctBy, SynthesisResult};
use sha3::{Digest, Sha3_256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const MAX_EVIDENCE_ITEMS: usize = 512;

/// Public ML-DSA verification keys indexed by governed authority identifier.
pub type AuthorityVerificationKeys = BTreeMap<String, Vec<u8>>;

/// Successful distributed authorization output before session-key derivation.
#[derive(Debug)]
pub struct AuthorizationResult {
    /// Secret output composed from every conjunctive policy clause.
    pub authorization_secret: Secret32,
    /// Session-bound input evaluated by all clause DPRFs.
    pub authorization_input: Digest32,
    /// Deterministically selected contributors for each clause.
    pub contributors: BTreeMap<String, Vec<String>>,
}

/// Final gateway result after both authorization and ML-KEM gates succeed.
#[derive(Debug)]
pub struct EstablishedSession {
    /// Final 256-bit session key.
    pub session_key: Secret32,
    /// Non-secret session-bound authorization input for audit correlation.
    pub authorization_input: Digest32,
    /// Selected authorization contributors by clause.
    pub contributors: BTreeMap<String, Vec<String>>,
}

/// Inputs required to complete both gateway trust gates.
pub struct SessionEstablishmentRequest<'a> {
    /// Canonical session context.
    pub context: &'a SessionContext,
    /// Deterministically synthesized authorization policy.
    pub synthesis: &'a SynthesisResult,
    /// Active proactive DPRF-share version.
    pub share_version: u64,
    /// Governed authority verification keys.
    pub verification_keys: &'a AuthorityVerificationKeys,
    /// Signed partial evaluations collected for the policy clauses.
    pub evidence: &'a [SignedPartialEvidence],
    /// ML-KEM shared secret held only by the gateway.
    pub kem_secret: &'a SecretBytes,
    /// Authenticated pre-handshake transcript.
    pub authenticated_transcript: &'a [u8],
    /// Rollback-protected state for the locally activated checkpoint.
    pub governance_state: &'a LocalGovernanceState,
    /// Locally cached checkpoint bundle.
    pub governance_checkpoint: &'a GovernanceCheckpoint,
    /// Current trusted Unix time.
    pub now: u64,
}

/// Verifies signed evidence and combines every required MT-CNF clause.
pub fn combine_authorization<B: DprfBackend>(
    provider: &PqProvider,
    backend: &B,
    context: &SessionContext,
    synthesis: &SynthesisResult,
    share_version: u64,
    verification_keys: &AuthorityVerificationKeys,
    evidence: &[SignedPartialEvidence],
) -> Result<AuthorizationResult, GatewayError> {
    context.validate()?;
    validate_structure(context, &synthesis.structure, &synthesis.policy_hash)?;
    if share_version == 0 {
        return Err(GatewayError::InvalidShareVersion);
    }
    if evidence.is_empty() || evidence.len() > MAX_EVIDENCE_ITEMS {
        return Err(GatewayError::InvalidEvidenceCount);
    }

    let input = authorization_input(context, &synthesis.policy_hash)?;
    let clause_ids: BTreeSet<&str> = synthesis
        .structure
        .clauses
        .iter()
        .map(|clause| clause.id.as_str())
        .collect();
    let mut seen = BTreeSet::new();

    for item in evidence {
        if item.policy_hash != synthesis.policy_hash {
            return Err(GatewayError::PolicyHashMismatch);
        }
        if !clause_ids.contains(item.partial.clause_id.as_str()) {
            return Err(GatewayError::UnexpectedClause(
                item.partial.clause_id.clone(),
            ));
        }
        let clause = synthesis
            .structure
            .clauses
            .iter()
            .find(|clause| clause.id == item.partial.clause_id)
            .ok_or_else(|| GatewayError::UnexpectedClause(item.partial.clause_id.clone()))?;
        if !clause
            .members
            .iter()
            .any(|member| member.authority_id == item.partial.authority_id)
        {
            return Err(GatewayError::IneligibleEvidence {
                clause: item.partial.clause_id.clone(),
                authority: item.partial.authority_id.clone(),
            });
        }
        if !seen.insert((
            item.partial.clause_id.clone(),
            item.partial.authority_id.clone(),
        )) {
            return Err(GatewayError::DuplicateEvidence {
                clause: item.partial.clause_id.clone(),
                authority: item.partial.authority_id.clone(),
            });
        }
        let public_key = verification_keys
            .get(&item.partial.authority_id)
            .ok_or_else(|| {
                GatewayError::MissingVerificationKey(item.partial.authority_id.clone())
            })?;
        verify_evidence(provider, public_key, context, item)?;
    }

    let mut clause_outputs = Vec::with_capacity(synthesis.structure.clauses.len());
    let mut contributors = BTreeMap::new();
    for clause in &synthesis.structure.clauses {
        let policy = ClausePolicy {
            clause_id: clause.id.clone(),
            threshold: clause.threshold,
            members: clause
                .members
                .iter()
                .map(|member| (member.authority_id.clone(), member.organization.clone()))
                .collect(),
            require_distinct_organizations: clause.distinct_by == DistinctBy::Organization,
        };
        let request = EvaluationRequest {
            clause_id: clause.id.clone(),
            epoch: context.epoch,
            share_version,
            input,
        };
        let partials: Vec<PartialEvaluation> = evidence
            .iter()
            .filter(|item| item.partial.clause_id == clause.id)
            .map(|item| item.partial.clone())
            .collect();
        let selected = validate_and_select(&policy, &request, &partials)?;
        contributors.insert(
            clause.id.clone(),
            selected
                .contributor_ids()
                .into_iter()
                .map(str::to_owned)
                .collect(),
        );
        let output = backend.combine(&policy, &request, &partials)?;
        clause_outputs.push((clause.id.as_str(), output));
    }

    let authorization_secret =
        compose_clause_outputs(&synthesis.policy_hash, &input, &clause_outputs);
    Ok(AuthorizationResult {
        authorization_secret,
        authorization_input: input,
        contributors,
    })
}

/// Completes authorization and derives a key requiring both DPRF and KEM secrets.
pub fn establish_session<B: DprfBackend>(
    provider: &PqProvider,
    backend: &B,
    request: SessionEstablishmentRequest<'_>,
) -> Result<EstablishedSession, GatewayError> {
    validate_cached_governance(
        request.context,
        request.governance_state,
        request.governance_checkpoint,
        request.now,
    )?;
    let authorization = combine_authorization(
        provider,
        backend,
        request.context,
        request.synthesis,
        request.share_version,
        request.verification_keys,
        request.evidence,
    )?;
    let session_key = derive_session_key(
        request.kem_secret,
        &authorization.authorization_secret,
        &authorization.authorization_input,
        request.authenticated_transcript,
    )?;
    Ok(EstablishedSession {
        session_key,
        authorization_input: authorization.authorization_input,
        contributors: authorization.contributors,
    })
}

/// Enforces epoch, digest, and bounded-staleness checks on cached governance.
pub fn validate_cached_governance(
    context: &SessionContext,
    state: &LocalGovernanceState,
    checkpoint: &GovernanceCheckpoint,
    now: u64,
) -> Result<(), GatewayError> {
    let digest = checkpoint_hash(checkpoint)?;
    if context.epoch != checkpoint.epoch
        || state.highest_epoch != checkpoint.epoch
        || context.checkpoint_hash != digest
        || state.checkpoint_hash != digest
    {
        return Err(GatewayError::GovernanceContextMismatch);
    }
    if !checkpoint_is_fresh(state, checkpoint, now) {
        return Err(GatewayError::StaleGovernanceCheckpoint);
    }
    Ok(())
}

fn validate_structure(
    context: &SessionContext,
    structure: &AuthorizationStructure,
    claimed_hash: &Digest32,
) -> Result<(), GatewayError> {
    if structure.version != 1 || structure.clauses.is_empty() || structure.risk != context.risk {
        return Err(GatewayError::InvalidAuthorizationStructure);
    }
    let mut clause_ids = BTreeSet::new();
    for clause in &structure.clauses {
        if clause.id.is_empty()
            || clause.threshold == 0
            || clause.members.len() < usize::from(clause.threshold)
            || !clause_ids.insert(clause.id.as_str())
        {
            return Err(GatewayError::InvalidAuthorizationStructure);
        }
    }
    let encoded = structure.encode_canonical()?;
    let actual_hash = hash_domain_separated(POLICY_HASH_LABEL, &[&encoded]);
    if actual_hash != *claimed_hash {
        return Err(GatewayError::PolicyHashMismatch);
    }
    Ok(())
}

fn compose_clause_outputs(
    policy_hash: &Digest32,
    input: &Digest32,
    clause_outputs: &[(&str, Secret32)],
) -> Secret32 {
    let mut hasher = Sha3_256::new();
    update_part(&mut hasher, AUTH_OUTPUT_LABEL);
    update_part(&mut hasher, policy_hash.as_bytes());
    update_part(&mut hasher, input.as_bytes());
    for (clause_id, output) in clause_outputs {
        update_part(&mut hasher, clause_id.as_bytes());
        update_part(&mut hasher, output.expose_secret());
    }
    Secret32::from_bytes(hasher.finalize().into())
}

fn update_part(hasher: &mut Sha3_256, part: &[u8]) {
    hasher.update((part.len() as u64).to_be_bytes());
    hasher.update(part);
}

/// Fail-closed gateway authorization and key-establishment errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum GatewayError {
    /// Shared protocol validation failed.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    /// Authority evidence validation failed.
    #[error(transparent)]
    Authority(#[from] AuthorityError),
    /// DPRF validation or combination failed.
    #[error(transparent)]
    Dprf(#[from] DprfError),
    /// Post-quantum key establishment failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// Off-path governance object validation failed.
    #[error(transparent)]
    Governance(#[from] GovernanceError),
    /// The synthesized structure is malformed or inconsistent with the context.
    #[error("invalid synthesized authorization structure")]
    InvalidAuthorizationStructure,
    /// The structure or evidence does not match the claimed policy hash.
    #[error("synthesized policy hash mismatch")]
    PolicyHashMismatch,
    /// The proactive-share version is zero.
    #[error("invalid proactive-share version")]
    InvalidShareVersion,
    /// The evidence batch is empty or exceeds its protocol bound.
    #[error("invalid authorization evidence count")]
    InvalidEvidenceCount,
    /// Evidence refers to a clause outside the synthesized policy.
    #[error("unexpected authorization clause: {0}")]
    UnexpectedClause(String),
    /// Evidence comes from an authority outside the specified clause.
    #[error("authority {authority} is ineligible for clause {clause}")]
    IneligibleEvidence {
        /// Clause identifier.
        clause: String,
        /// Authority identifier.
        authority: String,
    },
    /// More than one evidence item was submitted for an authority and clause.
    #[error("duplicate evidence from authority {authority} for clause {clause}")]
    DuplicateEvidence {
        /// Clause identifier.
        clause: String,
        /// Authority identifier.
        authority: String,
    },
    /// No governed ML-DSA verification key exists for the authority.
    #[error("missing verification key for authority {0}")]
    MissingVerificationKey(String),
    /// Session context and locally activated checkpoint differ.
    #[error("session context does not match the activated governance checkpoint")]
    GovernanceContextMismatch,
    /// The bounded offline-use window for the checkpoint has elapsed.
    #[error("cached governance checkpoint has expired")]
    StaleGovernanceCheckpoint,
}

#[cfg(test)]
mod tests {
    use super::*;
    use astra_authority::{AuthorityConfig, AuthorityEngine, AuthorityRequest};
    use astra_common::{PROTOCOL_VERSION, RiskClass, SessionId};
    use astra_synthesizer::{ClauseMember, ClausePurpose, SynthesisEvidence, ThresholdClause};

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
                payload: hash_domain_separated(b"TEST-PARTIAL", &[share, request.input.as_bytes()])
                    .as_bytes()
                    .to_vec(),
                proof: vec![],
            })
        }

        fn combine(
            &self,
            policy: &ClausePolicy,
            request: &EvaluationRequest,
            partials: &[PartialEvaluation],
        ) -> Result<Secret32, DprfError> {
            let selected = validate_and_select(policy, request, partials)?;
            let mut hasher = Sha3_256::new();
            for partial in selected.partials() {
                hasher.update(partial.payload.as_slice());
            }
            Ok(Secret32::from_bytes(hasher.finalize().into()))
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

    fn synthesis(context: &SessionContext) -> SynthesisResult {
        let structure = AuthorizationStructure {
            version: 1,
            risk: context.risk,
            destination_authority: "a2".to_owned(),
            clauses: vec![
                ThresholdClause {
                    id: "destination".to_owned(),
                    purpose: ClausePurpose::Destination,
                    threshold: 1,
                    distinct_by: DistinctBy::Authority,
                    members: vec![ClauseMember {
                        authority_id: "a2".to_owned(),
                        organization: "org-2".to_owned(),
                    }],
                },
                ThresholdClause {
                    id: "risk-floor".to_owned(),
                    purpose: ClausePurpose::RiskFloor,
                    threshold: 2,
                    distinct_by: DistinctBy::Organization,
                    members: vec![
                        ClauseMember {
                            authority_id: "a1".to_owned(),
                            organization: "org-1".to_owned(),
                        },
                        ClauseMember {
                            authority_id: "a2".to_owned(),
                            organization: "org-2".to_owned(),
                        },
                    ],
                },
            ],
        };
        let encoded = structure.encode_canonical().unwrap();
        SynthesisResult {
            policy_hash: hash_domain_separated(POLICY_HASH_LABEL, &[&encoded]),
            structure,
            evidence: SynthesisEvidence {
                considered_authorities: 2,
                eligible_authorities: 2,
                eligible_organizations: 2,
                required_organizations: 2,
            },
        }
    }

    fn request(
        context: &SessionContext,
        policy_hash: Digest32,
        clause_id: &str,
    ) -> AuthorityRequest {
        AuthorityRequest {
            context: context.clone(),
            policy_hash,
            evaluation: EvaluationRequest {
                clause_id: clause_id.to_owned(),
                epoch: context.epoch,
                share_version: 2,
                input: authorization_input(context, &policy_hash).unwrap(),
            },
        }
    }

    #[test]
    fn all_conjunctive_clauses_are_required_and_combined() {
        let context = context();
        let synthesis = synthesis(&context);
        let provider = PqProvider::new().unwrap();
        let keys_a1 = provider.generate_signature_keypair().unwrap();
        let keys_a2 = provider.generate_signature_keypair().unwrap();
        let backend = TestBackend;
        let share_a1 = [11; 32];
        let share_a2 = [12; 32];
        let common_config = |authority_id: &str, clauses: &[&str]| AuthorityConfig {
            authority_id: authority_id.to_owned(),
            active_epoch: 4,
            share_version: 2,
            approved_checkpoint: Digest32::from_bytes([3; 32]),
            allowed_clauses: clauses.iter().map(|clause| (*clause).to_owned()).collect(),
        };
        let mut a1 = AuthorityEngine::new(
            common_config("a1", &["risk-floor"]),
            &backend,
            &share_a1,
            &provider,
            keys_a1.secret_key(),
        );
        let mut a2 = AuthorityEngine::new(
            common_config("a2", &["destination", "risk-floor"]),
            &backend,
            &share_a2,
            &provider,
            keys_a2.secret_key(),
        );
        let evidence = vec![
            a2.authorize(&request(&context, synthesis.policy_hash, "destination"))
                .unwrap(),
            a1.authorize(&request(&context, synthesis.policy_hash, "risk-floor"))
                .unwrap(),
            a2.authorize(&request(&context, synthesis.policy_hash, "risk-floor"))
                .unwrap(),
        ];
        let verification_keys = BTreeMap::from([
            ("a1".to_owned(), keys_a1.public_key().to_vec()),
            ("a2".to_owned(), keys_a2.public_key().to_vec()),
        ]);
        let result = combine_authorization(
            &provider,
            &backend,
            &context,
            &synthesis,
            2,
            &verification_keys,
            &evidence,
        )
        .unwrap();
        assert_eq!(result.contributors["destination"], vec!["a2"]);
        assert_eq!(result.contributors["risk-floor"], vec!["a1", "a2"]);
        assert_eq!(
            result.authorization_input,
            authorization_input(&context, &synthesis.policy_hash).unwrap()
        );
    }

    #[test]
    fn cached_governance_expires_at_the_configured_boundary() {
        let mut context = context();
        let checkpoint = GovernanceCheckpoint {
            protocol_version: PROTOCOL_VERSION,
            epoch: context.epoch,
            predecessor_hash: Digest32::from_bytes([8; 32]),
            epoch_randomness: Digest32::from_bytes([1; 32]),
            registry_root: Digest32::from_bytes([2; 32]),
            independence_root: Digest32::from_bytes([3; 32]),
            policy_root: Digest32::from_bytes([4; 32]),
            revocation_root: Digest32::from_bytes([5; 32]),
            parameters_root: Digest32::from_bytes([6; 32]),
            activation_time: 1_700_000_000,
            maximum_age: 60,
        };
        let digest = checkpoint_hash(&checkpoint).unwrap();
        context.checkpoint_hash = digest;
        let state = LocalGovernanceState {
            highest_epoch: context.epoch,
            checkpoint_hash: digest,
            validated_at: 1_700_000_010,
            object_version: 9,
        };
        validate_cached_governance(&context, &state, &checkpoint, 1_700_000_070).unwrap();
        assert_eq!(
            validate_cached_governance(&context, &state, &checkpoint, 1_700_000_071),
            Err(GatewayError::StaleGovernanceCheckpoint)
        );
    }
}
