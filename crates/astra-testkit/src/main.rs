//! Reproducible in-process ASTRA-PQ smoke experiment.
//!
//! The deterministic DPRF backend in this executable is test-only. It checks
//! protocol composition but provides no threshold-DPRF security claim.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use anyhow::Context;
use astra_authority::{AuthorityConfig, AuthorityEngine, AuthorityRequest};
use astra_common::{
    Digest32, PROTOCOL_VERSION, RiskClass, Secret32, SessionContext, SessionId,
    authorization_input, hash_domain_separated,
};
use astra_dprf::{
    ClausePolicy, DprfBackend, DprfError, EvaluationRequest, PartialEvaluation, validate_and_select,
};
use astra_gateway::{AuthorityVerificationKeys, SessionEstablishmentRequest, establish_session};
use astra_governance::{
    CheckpointCandidate, GovernanceCheckpoint, GovernanceKeySet, GovernanceProfile,
    GovernanceSignature, LedgerAnchor, LocalGovernanceState, RpcObservation, checkpoint_hash,
    governance_signature_message, validate_and_activate,
};
use astra_pqcrypto::{PqProvider, SecretBytes};
use astra_synthesizer::{AuthorityRecord, SynthesisRequest, SynthesisResult, synthesize};
use serde_json::json;
use sha3::{Digest, Sha3_256};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

const NOW: u64 = 1_800_000_000;
const SHARE_VERSION: u64 = 1;

struct DeterministicTestBackend;

impl DprfBackend for DeterministicTestBackend {
    type Share = [u8; 32];

    fn backend_id(&self) -> &'static str {
        "deterministic-test-only-NOT-SECURE"
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
            payload: hash_domain_separated(
                b"ASTRA-PQ-TEST-PARTIAL-v1",
                &[
                    authority_id.as_bytes(),
                    request.clause_id.as_bytes(),
                    share,
                    request.input.as_bytes(),
                ],
            )
            .as_bytes()
            .to_vec(),
            proof: Vec::new(),
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
        hasher.update(b"ASTRA-PQ-TEST-COMBINE-v1");
        for partial in selected.partials() {
            hasher.update((partial.payload.len() as u64).to_be_bytes());
            hasher.update(partial.payload.as_slice());
        }
        Ok(Secret32::from_bytes(hasher.finalize().into()))
    }
}

fn main() -> anyhow::Result<()> {
    let total_start = Instant::now();
    let provider = PqProvider::new().context("initialize post-quantum provider")?;
    let backend = DeterministicTestBackend;

    let governance_start = Instant::now();
    let (checkpoint, governance_state) = activate_test_checkpoint(&provider)?;
    let governance_us = elapsed_microseconds(governance_start);
    let checkpoint_digest = checkpoint_hash(&checkpoint)?;

    let context = SessionContext {
        protocol_version: PROTOCOL_VERSION,
        session_id: SessionId::from_bytes([21; 32]),
        epoch: checkpoint.epoch,
        source_domain: "domain-a".to_owned(),
        destination_domain: "domain-b".to_owned(),
        subject: "operator:17".to_owned(),
        resource: "plc:4".to_owned(),
        action: "safety-actuation".to_owned(),
        risk: RiskClass::R3,
        gateway_transcript_hash: Digest32::from_bytes([22; 32]),
        checkpoint_hash: checkpoint_digest,
    };

    let synthesis_start = Instant::now();
    let synthesis = synthesize(&SynthesisRequest {
        context: context.clone(),
        authorities: authority_records(),
        required_roles: BTreeSet::new(),
        minimum_organizations: None,
    })
    .context("synthesize R3 authorization policy")?;
    let synthesis_us = elapsed_microseconds(synthesis_start);

    let keys_a1 = provider.generate_signature_keypair()?;
    let keys_a2 = provider.generate_signature_keypair()?;
    let keys_a3 = provider.generate_signature_keypair()?;
    let authority_start = Instant::now();
    let mut evidence = Vec::new();
    evidence.extend(issue_authority_evidence(
        &provider,
        &backend,
        "a1",
        &[31; 32],
        keys_a1.secret_key(),
        &context,
        &synthesis,
    )?);
    evidence.extend(issue_authority_evidence(
        &provider,
        &backend,
        "a2",
        &[32; 32],
        keys_a2.secret_key(),
        &context,
        &synthesis,
    )?);
    evidence.extend(issue_authority_evidence(
        &provider,
        &backend,
        "a3",
        &[33; 32],
        keys_a3.secret_key(),
        &context,
        &synthesis,
    )?);
    let authority_us = elapsed_microseconds(authority_start);

    let verification_keys: AuthorityVerificationKeys = BTreeMap::from([
        ("a1".to_owned(), keys_a1.public_key().to_vec()),
        ("a2".to_owned(), keys_a2.public_key().to_vec()),
        ("a3".to_owned(), keys_a3.public_key().to_vec()),
    ]);
    let responder_kem = provider.generate_kem_keypair()?;
    let encapsulation = provider.encapsulate(responder_kem.public_key())?;
    let decapsulated =
        provider.decapsulate(responder_kem.secret_key(), encapsulation.ciphertext())?;
    let transcript = b"authenticated ASTRA-PQ R3 smoke-test transcript";

    let initiator_start = Instant::now();
    let initiator = run_gateway(
        &provider,
        &backend,
        &context,
        &synthesis,
        &verification_keys,
        &evidence,
        encapsulation.shared_secret(),
        transcript,
        &governance_state,
        &checkpoint,
    )?;
    let initiator_us = elapsed_microseconds(initiator_start);

    let responder_start = Instant::now();
    let responder = run_gateway(
        &provider,
        &backend,
        &context,
        &synthesis,
        &verification_keys,
        &evidence,
        &decapsulated,
        transcript,
        &governance_state,
        &checkpoint,
    )?;
    let responder_us = elapsed_microseconds(responder_start);
    anyhow::ensure!(
        initiator.session_key.expose_secret() == responder.session_key.expose_secret(),
        "gateway session keys differ"
    );

    let metadata = provider.metadata();
    let report = json!({
        "schema": "astra-pq-smoke-v1",
        "success": true,
        "security_claim": false,
        "dprf_backend": backend.backend_id(),
        "warning": "The deterministic test DPRF validates composition only and is not a secure DPRF.",
        "risk_class": "R3",
        "epoch": context.epoch,
        "policy_hash": synthesis.policy_hash.to_string(),
        "clause_count": synthesis.structure.clauses.len(),
        "evidence_count": evidence.len(),
        "contributors": initiator.contributors,
        "kem": metadata.kem_algorithm,
        "signature": metadata.signature_algorithm,
        "timing_us": {
            "governance_validation": governance_us,
            "policy_synthesis": synthesis_us,
            "authority_issuance": authority_us,
            "initiator_gateway": initiator_us,
            "responder_gateway": responder_us,
            "total": elapsed_microseconds(total_start)
        }
    });
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn activate_test_checkpoint(
    provider: &PqProvider,
) -> anyhow::Result<(GovernanceCheckpoint, LocalGovernanceState)> {
    let checkpoint = GovernanceCheckpoint {
        protocol_version: PROTOCOL_VERSION,
        epoch: 1,
        predecessor_hash: Digest32::from_bytes([0; 32]),
        epoch_randomness: Digest32::from_bytes([1; 32]),
        registry_root: Digest32::from_bytes([2; 32]),
        independence_root: Digest32::from_bytes([3; 32]),
        policy_root: Digest32::from_bytes([4; 32]),
        revocation_root: Digest32::from_bytes([5; 32]),
        parameters_root: Digest32::from_bytes([6; 32]),
        activation_time: NOW - 10,
        maximum_age: 300,
    };
    let digest = checkpoint_hash(&checkpoint)?;
    let profile = GovernanceProfile {
        network_id: "iota-testnet".to_owned(),
        package_id: "0xastra".to_owned(),
        object_id: "0xgovernance".to_owned(),
        package_version: 1,
        rpc_quorum: 2,
    };
    let actor_1 = provider.generate_signature_keypair()?;
    let actor_2 = provider.generate_signature_keypair()?;
    let key_set = GovernanceKeySet {
        key_set_id: "test-governance-1".to_owned(),
        threshold: 2,
        members: BTreeMap::from([
            ("gov-1".to_owned(), actor_1.public_key().to_vec()),
            ("gov-2".to_owned(), actor_2.public_key().to_vec()),
        ]),
    };
    let message = governance_signature_message(
        &profile,
        &key_set.key_set_id,
        &digest,
        checkpoint.activation_time,
    )?;
    let signatures = vec![
        GovernanceSignature {
            actor_id: "gov-1".to_owned(),
            signature: provider.sign(actor_1.secret_key(), &message)?,
        },
        GovernanceSignature {
            actor_id: "gov-2".to_owned(),
            signature: provider.sign(actor_2.secret_key(), &message)?,
        },
    ];
    let transaction_digest = Digest32::from_bytes([7; 32]);
    let anchor = LedgerAnchor {
        network_id: profile.network_id.clone(),
        package_id: profile.package_id.clone(),
        object_id: profile.object_id.clone(),
        package_version: profile.package_version,
        epoch: checkpoint.epoch,
        predecessor_hash: checkpoint.predecessor_hash,
        checkpoint_hash: digest,
        activation_time: checkpoint.activation_time,
        object_version: 1,
        transaction_digest,
    };
    let observations = [
        RpcObservation {
            operator_id: "rpc-1".to_owned(),
            object_version: anchor.object_version,
            checkpoint_hash: digest,
            transaction_digest,
        },
        RpcObservation {
            operator_id: "rpc-2".to_owned(),
            object_version: anchor.object_version,
            checkpoint_hash: digest,
            transaction_digest,
        },
    ];
    let state = validate_and_activate(
        provider,
        CheckpointCandidate {
            current: &LocalGovernanceState::default(),
            checkpoint: &checkpoint,
            anchor: &anchor,
            observations: &observations,
            profile: &profile,
            key_set: &key_set,
            signatures: &signatures,
            now: NOW,
        },
    )?;
    Ok((checkpoint, state))
}

fn authority_records() -> Vec<AuthorityRecord> {
    vec![
        authority_record("a1", "domain-a", "org-1", &["source"], false),
        authority_record("a2", "domain-b", "org-2", &[], true),
        authority_record("a3", "safety-domain", "org-3", &["safety"], false),
    ]
}

fn authority_record(
    id: &str,
    domain: &str,
    organization: &str,
    roles: &[&str],
    is_destination_authority: bool,
) -> AuthorityRecord {
    AuthorityRecord {
        id: id.to_owned(),
        domain: domain.to_owned(),
        organization: organization.to_owned(),
        roles: roles.iter().map(|role| (*role).to_owned()).collect(),
        is_destination_authority,
        eligible: true,
        online: true,
        revoked: false,
    }
}

fn issue_authority_evidence(
    provider: &PqProvider,
    backend: &DeterministicTestBackend,
    authority_id: &str,
    share: &[u8; 32],
    signing_key: &SecretBytes,
    context: &SessionContext,
    synthesis: &SynthesisResult,
) -> anyhow::Result<Vec<astra_authority::SignedPartialEvidence>> {
    let assigned_clauses: Vec<String> = synthesis
        .structure
        .clauses
        .iter()
        .filter(|clause| {
            clause
                .members
                .iter()
                .any(|member| member.authority_id == authority_id)
        })
        .map(|clause| clause.id.clone())
        .collect();
    let config = AuthorityConfig {
        authority_id: authority_id.to_owned(),
        active_epoch: context.epoch,
        share_version: SHARE_VERSION,
        approved_checkpoint: context.checkpoint_hash,
        allowed_clauses: assigned_clauses.iter().cloned().collect(),
    };
    let mut engine = AuthorityEngine::new(config, backend, share, provider, signing_key);
    let input = authorization_input(context, &synthesis.policy_hash)?;
    assigned_clauses
        .into_iter()
        .map(|clause_id| {
            engine
                .authorize(&AuthorityRequest {
                    context: context.clone(),
                    policy_hash: synthesis.policy_hash,
                    evaluation: EvaluationRequest {
                        clause_id,
                        epoch: context.epoch,
                        share_version: SHARE_VERSION,
                        input,
                    },
                })
                .map_err(anyhow::Error::from)
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn run_gateway(
    provider: &PqProvider,
    backend: &DeterministicTestBackend,
    context: &SessionContext,
    synthesis: &SynthesisResult,
    verification_keys: &AuthorityVerificationKeys,
    evidence: &[astra_authority::SignedPartialEvidence],
    kem_secret: &SecretBytes,
    transcript: &[u8],
    governance_state: &LocalGovernanceState,
    governance_checkpoint: &GovernanceCheckpoint,
) -> anyhow::Result<astra_gateway::EstablishedSession> {
    establish_session(
        provider,
        backend,
        SessionEstablishmentRequest {
            context,
            synthesis,
            share_version: SHARE_VERSION,
            verification_keys,
            evidence,
            kem_secret,
            authenticated_transcript: transcript,
            governance_state,
            governance_checkpoint,
            now: NOW,
        },
    )
    .map_err(anyhow::Error::from)
}

fn elapsed_microseconds(start: Instant) -> u128 {
    start.elapsed().as_micros()
}
