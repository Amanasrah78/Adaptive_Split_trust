//! Shared protocol fixtures for the distributed ASTRA-PQ VM evaluation.
//!
//! This crate is evaluation infrastructure, not production configuration.
//! It centralizes the governed R3 authority registry so the initiator and
//! responder derive exactly the same canonical authorization structure.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod session_wire;
use astra_common::{RiskClass, SessionContext};
use astra_synthesizer::{
    AuthorityRecord, SynthesisError, SynthesisRequest, SynthesisResult, synthesize,
};
use std::collections::BTreeSet;

/// Active epoch used by the provisioned distributed-session experiment.
pub const SESSION_EPOCH: u64 = 1;

/// Active LWR share version used by the distributed-session experiment.
pub const SESSION_SHARE_VERSION: u64 = 1;

/// Builds the canonical four-clause R3 policy for the three-authority lab.
///
/// The policy requires destination authority `a2`, a three-organization risk
/// floor across `a1`, `a2`, and `a3`, source authority `a1`, and safety
/// authority `a3`.
pub fn r3_lab_synthesis(context: &SessionContext) -> Result<SynthesisResult, SynthesisError> {
    if context.risk != RiskClass::R3 {
        return Err(SynthesisError::InvalidField("session_risk"));
    }
    synthesize(&SynthesisRequest {
        context: context.clone(),
        authorities: r3_lab_authorities(),
        required_roles: BTreeSet::new(),
        minimum_organizations: None,
    })
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

    fn context() -> SessionContext {
        SessionContext {
            protocol_version: PROTOCOL_VERSION,
            session_id: SessionId::from_bytes([1; 32]),
            epoch: SESSION_EPOCH,
            source_domain: "domain-a".to_owned(),
            destination_domain: "domain-b".to_owned(),
            subject: "synthetic-operator:17".to_owned(),
            resource: "synthetic-plc:4".to_owned(),
            action: "synthetic-safety-actuation".to_owned(),
            risk: RiskClass::R3,
            gateway_transcript_hash: Digest32::from_bytes([2; 32]),
            checkpoint_hash: Digest32::from_bytes([3; 32]),
        }
    }

    #[test]
    fn r3_policy_is_canonical_and_complete() {
        let first = r3_lab_synthesis(&context()).unwrap();
        let second = r3_lab_synthesis(&context()).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.structure.destination_authority, "a2");
        assert_eq!(
            first
                .structure
                .clauses
                .iter()
                .map(|clause| clause.id.as_str())
                .collect::<Vec<_>>(),
            vec!["destination", "risk-floor", "safety", "source"]
        );
        assert_eq!(first.evidence.required_organizations, 3);
    }

    #[test]
    fn non_r3_context_is_rejected() {
        let mut invalid = context();
        invalid.risk = RiskClass::R4;
        assert_eq!(
            r3_lab_synthesis(&invalid),
            Err(SynthesisError::InvalidField("session_risk"))
        );
    }
}
