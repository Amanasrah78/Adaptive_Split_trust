//! Deterministic risk-aware MT-CNF synthesis for ASTRA-PQ.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use astra_common::{
    CanonicalEncode, Digest32, POLICY_HASH_LABEL, RiskClass, SessionContext, hash_domain_separated,
};
use minicbor::Encoder;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Governance and liveness information for an authorization authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityRecord {
    /// Stable authority identifier.
    pub id: String,
    /// Administrative domain containing the authority.
    pub domain: String,
    /// Governance-bound organization or independence class.
    pub organization: String,
    /// Governance-approved roles held by the authority.
    pub roles: BTreeSet<String>,
    /// True only for the resource owner's designated destination authority.
    pub is_destination_authority: bool,
    /// Governance eligibility for the active epoch.
    pub eligible: bool,
    /// Current health and availability status.
    pub online: bool,
    /// Current revocation status.
    pub revoked: bool,
}

impl AuthorityRecord {
    fn is_live(&self) -> bool {
        self.eligible && self.online && !self.revoked
    }

    fn has_role(&self, role: &str) -> bool {
        self.roles.contains(role)
    }
}

/// Inputs consumed by the deterministic policy synthesizer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesisRequest {
    /// Canonical session context.
    pub context: SessionContext,
    /// Current governance and liveness records.
    pub authorities: Vec<AuthorityRecord>,
    /// Additional roles required by the governed resource policy.
    pub required_roles: BTreeSet<String>,
    /// Optional organization-diversity floor above the risk-class default.
    pub minimum_organizations: Option<u16>,
}

/// The semantic purpose of a synthesized threshold clause.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClausePurpose {
    /// Mandatory destination-authority clause.
    Destination,
    /// Risk and organizational-diversity floor.
    RiskFloor,
    /// Source or independent oversight for a bounded write.
    SourceOrOversight,
    /// Mandatory source-domain contribution.
    Source,
    /// Independent safety-role contribution.
    Safety,
    /// Human confirmation for the highest risk class.
    HumanConfirmation,
    /// Additional governance-required role.
    RequiredRole,
}

impl ClausePurpose {
    const fn wire_value(self) -> u8 {
        match self {
            Self::Destination => 0,
            Self::RiskFloor => 1,
            Self::SourceOrOversight => 2,
            Self::Source => 3,
            Self::Safety => 4,
            Self::HumanConfirmation => 5,
            Self::RequiredRole => 6,
        }
    }
}

/// The independence dimension enforced while counting a clause threshold.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DistinctBy {
    /// Every qualifying authority counts independently.
    Authority,
    /// At most one qualifying contribution counts per organization.
    Organization,
}

impl DistinctBy {
    const fn wire_value(self) -> u8 {
        match self {
            Self::Authority => 0,
            Self::Organization => 1,
        }
    }
}

/// An authority leaf in a threshold clause.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClauseMember {
    /// Stable authority identifier.
    pub authority_id: String,
    /// Governance-bound organization used for distinct counting.
    pub organization: String,
}

/// One threshold clause in the normative MT-CNF policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdClause {
    /// Stable, deterministic clause identifier.
    pub id: String,
    /// Semantic clause purpose.
    pub purpose: ClausePurpose,
    /// Required number of qualifying members.
    pub threshold: u16,
    /// Dimension under which qualifying members must be distinct.
    pub distinct_by: DistinctBy,
    /// Sorted eligible clause members.
    pub members: Vec<ClauseMember>,
}

/// A synthesized monotone threshold-conjunctive authorization structure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationStructure {
    /// Structure-format version.
    pub version: u16,
    /// Risk class that selected the normative floor.
    pub risk: RiskClass,
    /// Mandatory destination authority.
    pub destination_authority: String,
    /// Conjunctive list of threshold clauses.
    pub clauses: Vec<ThresholdClause>,
}

impl CanonicalEncode for AuthorizationStructure {
    fn encode_canonical(&self) -> Result<Vec<u8>, astra_common::ProtocolError> {
        let mut bytes = Vec::new();
        let mut encoder = Encoder::new(&mut bytes);

        macro_rules! encode {
            ($operation:expr) => {
                $operation
                    .map_err(|error| astra_common::ProtocolError::Encoding(error.to_string()))?;
            };
        }

        encode!(encoder.map(4));
        encode!(encoder.u8(0));
        encode!(encoder.u16(self.version));
        encode!(encoder.u8(1));
        encode!(encoder.u8(self.risk.wire_value()));
        encode!(encoder.u8(2));
        encode!(encoder.str(&self.destination_authority));
        encode!(encoder.u8(3));
        encode!(encoder.array(self.clauses.len() as u64));

        for clause in &self.clauses {
            encode!(encoder.map(5));
            encode!(encoder.u8(0));
            encode!(encoder.str(&clause.id));
            encode!(encoder.u8(1));
            encode!(encoder.u8(clause.purpose.wire_value()));
            encode!(encoder.u8(2));
            encode!(encoder.u16(clause.threshold));
            encode!(encoder.u8(3));
            encode!(encoder.u8(clause.distinct_by.wire_value()));
            encode!(encoder.u8(4));
            encode!(encoder.array(clause.members.len() as u64));
            for member in &clause.members {
                encode!(encoder.array(2));
                encode!(encoder.str(&member.authority_id));
                encode!(encoder.str(&member.organization));
            }
        }

        Ok(bytes)
    }
}

/// Auditable, non-secret synthesis metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesisEvidence {
    /// Number of governance records considered.
    pub considered_authorities: usize,
    /// Number of currently live and eligible authorities.
    pub eligible_authorities: usize,
    /// Number of distinct eligible organizations.
    pub eligible_organizations: usize,
    /// Effective organization-diversity floor.
    pub required_organizations: u16,
}

/// Complete deterministic synthesis output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesisResult {
    /// Synthesized MT-CNF structure.
    pub structure: AuthorizationStructure,
    /// Domain-separated canonical structure hash.
    pub policy_hash: Digest32,
    /// Auditable synthesis metadata.
    pub evidence: SynthesisEvidence,
}

/// Deterministically synthesizes a feasible ASTRA-PQ MT-CNF structure.
pub fn synthesize(request: &SynthesisRequest) -> Result<SynthesisResult, SynthesisError> {
    request.context.validate()?;
    validate_records(&request.authorities)?;

    let mut live: Vec<&AuthorityRecord> = request
        .authorities
        .iter()
        .filter(|authority| authority.is_live())
        .collect();
    live.sort_by(|left, right| left.id.cmp(&right.id));

    let destinations: Vec<&AuthorityRecord> = live
        .iter()
        .copied()
        .filter(|authority| {
            authority.is_destination_authority
                && authority.domain == request.context.destination_domain
        })
        .collect();
    let destination = match destinations.as_slice() {
        [authority] => *authority,
        [] => return Err(SynthesisError::DestinationUnavailable),
        _ => return Err(SynthesisError::AmbiguousDestination),
    };

    let risk_floor = request.context.risk.minimum_authorities();
    let required_organizations = request
        .minimum_organizations
        .unwrap_or(risk_floor)
        .max(risk_floor);
    let organizations: BTreeSet<&str> = live
        .iter()
        .map(|authority| authority.organization.as_str())
        .collect();
    if organizations.len() < usize::from(required_organizations) {
        return Err(SynthesisError::InsufficientOrganizations {
            required: required_organizations,
            available: organizations.len(),
        });
    }

    let mut clauses = vec![ThresholdClause {
        id: "destination".to_owned(),
        purpose: ClausePurpose::Destination,
        threshold: 1,
        distinct_by: DistinctBy::Authority,
        members: members([destination]),
    }];

    if required_organizations > 1 {
        clauses.push(ThresholdClause {
            id: "risk-floor".to_owned(),
            purpose: ClausePurpose::RiskFloor,
            threshold: required_organizations,
            distinct_by: DistinctBy::Organization,
            members: members(live.iter().copied()),
        });
    }

    let mut covered_roles = BTreeSet::new();
    match request.context.risk {
        RiskClass::R0 | RiskClass::R1 => {}
        RiskClass::R2 => {
            clauses.push(select_clause(
                "source-or-oversight",
                ClausePurpose::SourceOrOversight,
                &live,
                |authority| {
                    (authority.domain == request.context.source_domain
                        && authority.has_role("source"))
                        || authority.has_role("oversight")
                },
            )?);
            covered_roles.insert("source");
            covered_roles.insert("oversight");
        }
        RiskClass::R3 | RiskClass::R4 => {
            clauses.push(select_clause(
                "source",
                ClausePurpose::Source,
                &live,
                |authority| {
                    authority.domain == request.context.source_domain
                        && authority.has_role("source")
                },
            )?);
            clauses.push(select_clause(
                "safety",
                ClausePurpose::Safety,
                &live,
                |authority| authority.has_role("safety"),
            )?);
            covered_roles.insert("source");
            covered_roles.insert("safety");
        }
    }

    if request.context.risk == RiskClass::R4 {
        clauses.push(select_clause(
            "human-confirmation",
            ClausePurpose::HumanConfirmation,
            &live,
            |authority| authority.has_role("human-confirmation"),
        )?);
        covered_roles.insert("human-confirmation");
    }

    for role in &request.required_roles {
        validate_text("required_role", role)?;
        if covered_roles.contains(role.as_str()) {
            continue;
        }
        clauses.push(select_clause(
            &format!("role:{role}"),
            ClausePurpose::RequiredRole,
            &live,
            |authority| authority.has_role(role),
        )?);
    }

    clauses.sort_by(|left, right| left.id.cmp(&right.id));
    let structure = AuthorizationStructure {
        version: 1,
        risk: request.context.risk,
        destination_authority: destination.id.clone(),
        clauses,
    };
    let encoded = structure.encode_canonical()?;
    let policy_hash = hash_domain_separated(POLICY_HASH_LABEL, &[encoded.as_slice()]);

    Ok(SynthesisResult {
        structure,
        policy_hash,
        evidence: SynthesisEvidence {
            considered_authorities: request.authorities.len(),
            eligible_authorities: live.len(),
            eligible_organizations: organizations.len(),
            required_organizations,
        },
    })
}

fn select_clause<F>(
    id: &str,
    purpose: ClausePurpose,
    live: &[&AuthorityRecord],
    predicate: F,
) -> Result<ThresholdClause, SynthesisError>
where
    F: Fn(&AuthorityRecord) -> bool,
{
    let selected: Vec<&AuthorityRecord> = live
        .iter()
        .copied()
        .filter(|authority| predicate(authority))
        .collect();
    if selected.is_empty() {
        return Err(SynthesisError::UnsatisfiedClause(id.to_owned()));
    }
    Ok(ThresholdClause {
        id: id.to_owned(),
        purpose,
        threshold: 1,
        distinct_by: DistinctBy::Authority,
        members: members(selected),
    })
}

fn members<'a>(authorities: impl IntoIterator<Item = &'a AuthorityRecord>) -> Vec<ClauseMember> {
    let mut members: Vec<ClauseMember> = authorities
        .into_iter()
        .map(|authority| ClauseMember {
            authority_id: authority.id.clone(),
            organization: authority.organization.clone(),
        })
        .collect();
    members.sort_by(|left, right| {
        left.authority_id
            .cmp(&right.authority_id)
            .then_with(|| left.organization.cmp(&right.organization))
    });
    members
}

fn validate_records(authorities: &[AuthorityRecord]) -> Result<(), SynthesisError> {
    let mut identifiers = BTreeMap::new();
    for authority in authorities {
        validate_text("authority_id", &authority.id)?;
        validate_text("authority_domain", &authority.domain)?;
        validate_text("authority_organization", &authority.organization)?;
        if identifiers.insert(authority.id.as_str(), ()).is_some() {
            return Err(SynthesisError::DuplicateAuthority(authority.id.clone()));
        }
        for role in &authority.roles {
            validate_text("authority_role", role)?;
        }
    }
    Ok(())
}

fn validate_text(field: &'static str, value: &str) -> Result<(), SynthesisError> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(SynthesisError::InvalidField(field));
    }
    Ok(())
}

/// Fail-closed synthesis errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SynthesisError {
    /// Session-context validation failed.
    #[error(transparent)]
    Protocol(#[from] astra_common::ProtocolError),
    /// A governance record contains a malformed bounded string.
    #[error("invalid synthesis field: {0}")]
    InvalidField(&'static str),
    /// Two governance records use the same authority identifier.
    #[error("duplicate authority identifier: {0}")]
    DuplicateAuthority(String),
    /// No live destination authority is available.
    #[error("the destination authority is unavailable")]
    DestinationUnavailable,
    /// More than one live authority claims the unique destination role.
    #[error("the destination authority designation is ambiguous")]
    AmbiguousDestination,
    /// The current live set cannot meet the organization-diversity floor.
    #[error("insufficient organizations: required {required}, available {available}")]
    InsufficientOrganizations {
        /// Required number of distinct organizations.
        required: u16,
        /// Available number of distinct organizations.
        available: usize,
    },
    /// A mandatory role clause has no currently live member.
    #[error("mandatory clause has no eligible member: {0}")]
    UnsatisfiedClause(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use astra_common::{Digest32, PROTOCOL_VERSION, SessionId};

    fn roles(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn authority(
        id: &str,
        domain: &str,
        organization: &str,
        assigned_roles: &[&str],
        destination: bool,
    ) -> AuthorityRecord {
        AuthorityRecord {
            id: id.to_owned(),
            domain: domain.to_owned(),
            organization: organization.to_owned(),
            roles: roles(assigned_roles),
            is_destination_authority: destination,
            eligible: true,
            online: true,
            revoked: false,
        }
    }

    fn context(risk: RiskClass) -> SessionContext {
        SessionContext {
            protocol_version: PROTOCOL_VERSION,
            session_id: SessionId::from_bytes([1; 32]),
            epoch: 8,
            issued_at_unix: 100,
            expires_at_unix: 200,
            request_nonce: astra_common::RequestNonce::from_bytes([4; 32]),
            source_domain: "domain-a".to_owned(),
            destination_domain: "domain-b".to_owned(),
            subject: "operator:17".to_owned(),
            resource: "plc:4".to_owned(),
            action: "bounded-write".to_owned(),
            risk,
            gateway_transcript_hash: Digest32::from_bytes([2; 32]),
            checkpoint_hash: Digest32::from_bytes([3; 32]),
        }
    }

    fn request(risk: RiskClass) -> SynthesisRequest {
        SynthesisRequest {
            context: context(risk),
            authorities: vec![
                authority("a1", "domain-b", "org-1", &["destination"], true),
                authority("a2", "domain-a", "org-2", &["source"], false),
                authority("a3", "domain-c", "org-3", &["safety"], false),
                authority("a4", "domain-d", "org-4", &["human-confirmation"], false),
                authority("a5", "domain-e", "org-5", &["oversight"], false),
            ],
            required_roles: BTreeSet::new(),
            minimum_organizations: None,
        }
    }

    #[test]
    fn r0_requires_only_the_destination_clause() {
        let result = synthesize(&request(RiskClass::R0)).unwrap();
        assert_eq!(result.structure.clauses.len(), 1);
        assert_eq!(
            result.structure.clauses[0].purpose,
            ClausePurpose::Destination
        );
    }

    #[test]
    fn r3_contains_destination_risk_source_and_safety_clauses() {
        let result = synthesize(&request(RiskClass::R3)).unwrap();
        let purposes: BTreeSet<u8> = result
            .structure
            .clauses
            .iter()
            .map(|clause| clause.purpose.wire_value())
            .collect();
        assert_eq!(purposes, BTreeSet::from([0, 1, 3, 4]));
        assert_eq!(result.evidence.required_organizations, 3);
    }

    #[test]
    fn synthesis_and_policy_hash_are_deterministic() {
        let first = synthesize(&request(RiskClass::R4)).unwrap();
        let second = synthesize(&request(RiskClass::R4)).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn revoked_safety_authority_causes_fail_closed_rejection() {
        let mut input = request(RiskClass::R3);
        input.authorities[2].revoked = true;
        assert_eq!(
            synthesize(&input),
            Err(SynthesisError::UnsatisfiedClause("safety".to_owned()))
        );
    }
}
