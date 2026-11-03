//! Shared protocol fixtures for the distributed ASTRA-PQ VM evaluation.
//!
//! This crate is evaluation infrastructure, not production configuration.
//! It centralizes the governed, risk-adaptive authority registries so the
//! initiator and responder derive exactly the same authorization structure.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod replay_store;
pub mod session_wire;

use astra_common::{RiskClass, SessionContext};
use astra_synthesizer::{
    AuthorityRecord, SynthesisError, SynthesisRequest, SynthesisResult, synthesize,
};
use std::collections::BTreeSet;

/// Active epoch used by the provisioned distributed-session experiment.
pub const SESSION_EPOCH: u64 = 2;

/// Active LWR share version used by the distributed-session experiment.
pub const SESSION_SHARE_VERSION: u64 = 1;

/// Builds the governed, risk-adaptive policy for the VM laboratory.
///
/// The eligible authorization committee expands with risk. R0 uses the
/// destination authority, R1 and R2 use two organizations, R3 uses three,
/// and R4 uses four. R4 deliberately raises the synthesizer's default floor
/// from three to four organizations as a governed high-consequence override.
/// Each resulting threshold clause is therefore an exact coalition, matching
/// the currently implemented LWR backend.
pub fn adaptive_lab_synthesis(context: &SessionContext) -> Result<SynthesisResult, SynthesisError> {
    let minimum_organizations = match context.risk {
        RiskClass::R4 => Some(4),
        RiskClass::R0 | RiskClass::R1 | RiskClass::R2 | RiskClass::R3 => None,
    };
    synthesize(&SynthesisRequest {
        context: context.clone(),
        authorities: adaptive_lab_authorities(context.risk),
        required_roles: BTreeSet::new(),
        minimum_organizations,
    })
}

/// Builds the canonical four-clause R3 policy for the three-authority lab.
///
/// This compatibility wrapper preserves the validated v0.7.0 R3 behavior.
pub fn r3_lab_synthesis(context: &SessionContext) -> Result<SynthesisResult, SynthesisError> {
    if context.risk != RiskClass::R3 {
        return Err(SynthesisError::InvalidField("session_risk"));
    }
    adaptive_lab_synthesis(context)
}

/// Returns the governed authority registry eligible for a risk class.
#[must_use]
pub fn adaptive_lab_authorities(risk: RiskClass) -> Vec<AuthorityRecord> {
    match risk {
        RiskClass::R0 => vec![authority("a2", "domain-b", "org-2", &[], true)],
        RiskClass::R1 | RiskClass::R2 => vec![
            authority("a1", "domain-a", "org-1", &["source"], false),
            authority("a2", "domain-b", "org-2", &[], true),
        ],
        RiskClass::R3 => r3_lab_authorities(),
        RiskClass::R4 => vec![
            authority("a1", "domain-a", "org-1", &["source"], false),
            authority("a2", "domain-b", "org-2", &[], true),
            authority("a3", "safety-domain", "org-3", &["safety"], false),
            authority(
                "a4",
                "human-oversight-domain",
                "org-4",
                &["human-confirmation"],
                false,
            ),
        ],
    }
}

/// Returns the governed authority registry used by the R3 session experiment.
#[must_use]
pub fn r3_lab_authorities() -> Vec<AuthorityRecord> {
    vec![
        authority("a1", "domain-a", "org-1", &["source"], false),
        authority("a2", "domain-b", "org-2", &[], true),
        authority("a3", "safety-domain", "org-3", &["safety"], false),
    ]
}

fn authority(
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

#[cfg(test)]
mod tests {
    use super::*;
    use astra_common::{Digest32, PROTOCOL_VERSION, SessionId};

    fn context(risk: RiskClass) -> SessionContext {
        SessionContext {
            protocol_version: PROTOCOL_VERSION,
            session_id: SessionId::from_bytes([1; 32]),
            epoch: SESSION_EPOCH,
            issued_at_unix: 100,
            expires_at_unix: 200,
            request_nonce: astra_common::RequestNonce::from_bytes([4; 32]),
            source_domain: "domain-a".to_owned(),
            destination_domain: "domain-b".to_owned(),
            subject: "synthetic-operator:17".to_owned(),
            resource: "synthetic-plc:4".to_owned(),
            action: "synthetic-safety-actuation".to_owned(),
            risk,
            gateway_transcript_hash: Digest32::from_bytes([2; 32]),
            checkpoint_hash: Digest32::from_bytes([3; 32]),
        }
    }

    #[test]
    fn adaptive_policies_are_deterministic_and_exact() {
        let expectations = [
            (RiskClass::R0, 1_usize, 1_u16),
            (RiskClass::R1, 3, 2),
            (RiskClass::R2, 4, 2),
            (RiskClass::R3, 6, 3),
            (RiskClass::R4, 8, 4),
        ];

        for (risk, expected_evidence, expected_floor) in expectations {
            let first = adaptive_lab_synthesis(&context(risk)).unwrap();
            let second = adaptive_lab_synthesis(&context(risk)).unwrap();
            assert_eq!(first, second);
            assert_eq!(first.structure.destination_authority, "a2");
            assert_eq!(first.evidence.required_organizations, expected_floor);
            assert!(
                first
                    .structure
                    .clauses
                    .iter()
                    .all(|clause| { clause.members.len() == usize::from(clause.threshold) })
            );
            assert_eq!(
                first
                    .structure
                    .clauses
                    .iter()
                    .map(|clause| clause.members.len())
                    .sum::<usize>(),
                expected_evidence
            );
        }
    }

    #[test]
    fn r3_wrapper_preserves_the_validated_policy() {
        let result = r3_lab_synthesis(&context(RiskClass::R3)).unwrap();
        assert_eq!(
            result
                .structure
                .clauses
                .iter()
                .map(|clause| clause.id.as_str())
                .collect::<Vec<_>>(),
            vec!["destination", "risk-floor", "safety", "source"]
        );
        assert_eq!(result.evidence.required_organizations, 3);
    }

    #[test]
    fn r4_requires_independent_human_confirmation() {
        let result = adaptive_lab_synthesis(&context(RiskClass::R4)).unwrap();
        let human = result
            .structure
            .clauses
            .iter()
            .find(|clause| clause.id == "human-confirmation")
            .unwrap();
        assert_eq!(human.threshold, 1);
        assert_eq!(human.members.len(), 1);
        assert_eq!(human.members[0].authority_id, "a4");
        assert_eq!(result.evidence.required_organizations, 4);
    }

    #[test]
    fn r3_wrapper_rejects_other_risks() {
        assert_eq!(
            r3_lab_synthesis(&context(RiskClass::R4)),
            Err(SynthesisError::InvalidField("session_risk"))
        );
    }
}
