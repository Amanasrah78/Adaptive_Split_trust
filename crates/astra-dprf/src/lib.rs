//! Backend boundary and fail-closed validation for ASTRA-PQ clause DPRFs.
//!
//! This crate does not claim that an arbitrary backend is secure. Production
//! deployments must provide a reviewed robust post-quantum DPRF implementation.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use astra_common::Digest32;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use zeroize::Zeroize;

const MAX_PARTIAL_BYTES: usize = 65_536;
const MAX_PROOF_BYTES: usize = 65_536;

/// Clause policy consumed by a DPRF combiner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClausePolicy {
    /// Governance-approved clause identifier.
    pub clause_id: String,
    /// Required number of qualifying partial evaluations.
    pub threshold: u16,
    /// Mapping from eligible authority identifiers to independence classes.
    pub members: BTreeMap<String, String>,
    /// Whether at most one partial counts from each independence class.
    pub require_distinct_organizations: bool,
}

impl ClausePolicy {
    /// Validates the bounded clause policy.
    pub fn validate(&self) -> Result<(), DprfError> {
        validate_text("clause_id", &self.clause_id)?;
        if self.threshold == 0 {
            return Err(DprfError::InvalidThreshold);
        }
        if self.members.len() < usize::from(self.threshold) {
            return Err(DprfError::InsufficientEligibleMembers);
        }
        for (authority, organization) in &self.members {
            validate_text("authority_id", authority)?;
            validate_text("organization", organization)?;
        }
        if self.require_distinct_organizations {
            let organizations: BTreeSet<&str> = self.members.values().map(String::as_str).collect();
            if organizations.len() < usize::from(self.threshold) {
                return Err(DprfError::InsufficientEligibleOrganizations);
            }
        }
        Ok(())
    }
}

/// Session-bound input supplied to one clause-DPRF instance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluationRequest {
    /// Governance-approved clause identifier.
    pub clause_id: String,
    /// Active authorization epoch.
    pub epoch: u64,
    /// Expected proactive share version.
    pub share_version: u64,
    /// Session-bound distributed-PRF input.
    pub input: Digest32,
}

impl EvaluationRequest {
    /// Validates request bounds and nonzero epoch versions.
    pub fn validate(&self) -> Result<(), DprfError> {
        validate_text("clause_id", &self.clause_id)?;
        if self.epoch == 0 {
            return Err(DprfError::InvalidEpoch);
        }
        if self.share_version == 0 {
            return Err(DprfError::InvalidShareVersion);
        }
        if self.input.is_zero() {
            return Err(DprfError::InvalidInput);
        }
        Ok(())
    }
}

/// Opaque authority output returned by a concrete DPRF backend.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartialEvaluation {
    /// Authority that produced the partial evaluation.
    pub authority_id: String,
    /// Clause key used for evaluation.
    pub clause_id: String,
    /// Authorization epoch bound to the partial.
    pub epoch: u64,
    /// Proactive share version bound to the partial.
    pub share_version: u64,
    /// Session-bound input evaluated by the authority.
    pub input: Digest32,
    /// Backend-specific partial-evaluation bytes.
    pub payload: Vec<u8>,
    /// Backend-specific robustness proof or authentication data.
    pub proof: Vec<u8>,
}

/// Deterministically selected qualifying partial evaluations.
#[derive(Debug, PartialEq, Eq)]
pub struct ValidatedPartialSet<'a> {
    partials: Vec<&'a PartialEvaluation>,
}

impl<'a> ValidatedPartialSet<'a> {
    /// Returns qualifying partials sorted by authority identifier.
    #[must_use]
    pub fn partials(&self) -> &[&'a PartialEvaluation] {
        &self.partials
    }

    /// Returns the sorted qualifying authority identifiers.
    #[must_use]
    pub fn contributor_ids(&self) -> Vec<&'a str> {
        self.partials
            .iter()
            .map(|partial| partial.authority_id.as_str())
            .collect()
    }
}

/// Validates partials and chooses one deterministic threshold subset.
pub fn validate_and_select<'a>(
    policy: &ClausePolicy,
    request: &EvaluationRequest,
    partials: &'a [PartialEvaluation],
) -> Result<ValidatedPartialSet<'a>, DprfError> {
    policy.validate()?;
    request.validate()?;
    if policy.clause_id != request.clause_id {
        return Err(DprfError::ClauseMismatch);
    }

    let mut seen_authorities = BTreeSet::new();
    let mut candidates = Vec::with_capacity(partials.len());
    for partial in partials {
        validate_text("partial_authority_id", &partial.authority_id)?;
        if !seen_authorities.insert(partial.authority_id.as_str()) {
            return Err(DprfError::DuplicateAuthority(partial.authority_id.clone()));
        }
        if !policy.members.contains_key(&partial.authority_id) {
            return Err(DprfError::IneligibleAuthority(partial.authority_id.clone()));
        }
        if partial.clause_id != request.clause_id {
            return Err(DprfError::ClauseMismatch);
        }
        if partial.epoch != request.epoch {
            return Err(DprfError::EpochMismatch);
        }
        if partial.share_version != request.share_version {
            return Err(DprfError::ShareVersionMismatch);
        }
        if partial.input != request.input {
            return Err(DprfError::InputMismatch);
        }
        if partial.payload.is_empty() || partial.payload.len() > MAX_PARTIAL_BYTES {
            return Err(DprfError::InvalidPartialLength);
        }
        if partial.proof.len() > MAX_PROOF_BYTES {
            return Err(DprfError::InvalidProofLength);
        }
        candidates.push(partial);
    }

    candidates.sort_by(|left, right| left.authority_id.cmp(&right.authority_id));
    let mut selected = Vec::with_capacity(usize::from(policy.threshold));
    let mut selected_organizations = BTreeSet::new();
    for partial in candidates {
        let organization = policy
            .members
            .get(&partial.authority_id)
            .ok_or_else(|| DprfError::IneligibleAuthority(partial.authority_id.clone()))?;
        if policy.require_distinct_organizations
            && !selected_organizations.insert(organization.as_str())
        {
            continue;
        }
        selected.push(partial);
        if selected.len() == usize::from(policy.threshold) {
            break;
        }
    }

    if selected.len() < usize::from(policy.threshold) {
        return Err(DprfError::ThresholdNotMet {
            required: policy.threshold,
            qualifying: selected.len(),
        });
    }
    Ok(ValidatedPartialSet { partials: selected })
}

/// Backend abstraction for one concrete post-quantum DPRF construction.
pub trait DprfBackend {
    /// Secret share representation owned by one authority process.
    type Share: Zeroize;

    /// Human-readable backend and parameter-set identifier.
    fn backend_id(&self) -> &'static str;

    /// Computes one session-bound partial evaluation without exposing the share.
    fn partial_evaluate(
        &self,
        authority_id: &str,
        share: &Self::Share,
        request: &EvaluationRequest,
    ) -> Result<PartialEvaluation, DprfError>;

    /// Verifies and combines a qualifying set into a clause output.
    fn combine(
        &self,
        policy: &ClausePolicy,
        request: &EvaluationRequest,
        partials: &[PartialEvaluation],
    ) -> Result<Digest32, DprfError>;
}

/// Optional extension implemented by backends supporting proactive refresh.
pub trait ProactiveRefreshBackend: DprfBackend {
    /// Applies an authenticated refresh contribution and advances the share version.
    fn refresh_share(
        &self,
        share: &mut Self::Share,
        current_epoch: u64,
        next_epoch: u64,
        refresh_contribution: &[u8],
    ) -> Result<(), DprfError>;
}

fn validate_text(field: &'static str, value: &str) -> Result<(), DprfError> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(DprfError::InvalidField(field));
    }
    Ok(())
}

/// Errors produced by DPRF request, partial, and backend validation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DprfError {
    /// A bounded textual field is malformed.
    #[error("invalid DPRF field: {0}")]
    InvalidField(&'static str),
    /// The threshold is zero.
    #[error("the clause threshold must be positive")]
    InvalidThreshold,
    /// The member list contains fewer authorities than the threshold.
    #[error("the clause has insufficient eligible members")]
    InsufficientEligibleMembers,
    /// The member list contains fewer organizations than the distinct threshold.
    #[error("the clause has insufficient eligible organizations")]
    InsufficientEligibleOrganizations,
    /// The authorization epoch is zero.
    #[error("the DPRF epoch must be positive")]
    InvalidEpoch,
    /// The proactive share version is zero.
    #[error("the DPRF share version must be positive")]
    InvalidShareVersion,
    /// The session-bound input is all zero.
    #[error("the DPRF input is invalid")]
    InvalidInput,
    /// Policy, request, or partial clause identifiers differ.
    #[error("DPRF clause identifier mismatch")]
    ClauseMismatch,
    /// The same authority submitted more than one partial.
    #[error("duplicate partial from authority {0}")]
    DuplicateAuthority(String),
    /// A partial was produced by an authority outside the governed member set.
    #[error("ineligible authority {0}")]
    IneligibleAuthority(String),
    /// A partial is bound to a different epoch.
    #[error("DPRF epoch mismatch")]
    EpochMismatch,
    /// A partial is bound to a different proactive share version.
    #[error("DPRF share-version mismatch")]
    ShareVersionMismatch,
    /// A partial is bound to a different session input.
    #[error("DPRF input mismatch")]
    InputMismatch,
    /// A partial payload is empty or exceeds its bound.
    #[error("invalid DPRF partial length")]
    InvalidPartialLength,
    /// A robustness proof exceeds its bound.
    #[error("invalid DPRF proof length")]
    InvalidProofLength,
    /// Too few qualifying partials remain after validation.
    #[error("DPRF threshold not met: required {required}, qualifying {qualifying}")]
    ThresholdNotMet {
        /// Required threshold.
        required: u16,
        /// Number of qualifying partials.
        qualifying: usize,
    },
    /// A concrete backend rejected an operation.
    #[error("DPRF backend failure: {0}")]
    Backend(String),
    /// A refresh transition is malformed or non-monotonic.
    #[error("invalid proactive refresh transition")]
    InvalidRefreshTransition,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(distinct: bool) -> ClausePolicy {
        ClausePolicy {
            clause_id: "risk-floor".to_owned(),
            threshold: 2,
            members: BTreeMap::from([
                ("a1".to_owned(), "org-1".to_owned()),
                ("a2".to_owned(), "org-1".to_owned()),
                ("a3".to_owned(), "org-2".to_owned()),
            ]),
            require_distinct_organizations: distinct,
        }
    }

    fn request() -> EvaluationRequest {
        EvaluationRequest {
            clause_id: "risk-floor".to_owned(),
            epoch: 9,
            share_version: 3,
            input: Digest32::from_bytes([7; 32]),
        }
    }

    fn partial(authority: &str, marker: u8) -> PartialEvaluation {
        PartialEvaluation {
            authority_id: authority.to_owned(),
            clause_id: "risk-floor".to_owned(),
            epoch: 9,
            share_version: 3,
            input: Digest32::from_bytes([7; 32]),
            payload: vec![marker; 32],
            proof: vec![],
        }
    }

    #[test]
    fn partial_selection_is_deterministic() {
        let first = vec![partial("a3", 3), partial("a1", 1), partial("a2", 2)];
        let second = vec![partial("a2", 2), partial("a3", 3), partial("a1", 1)];
        let first_selected = validate_and_select(&policy(false), &request(), &first).unwrap();
        let second_selected = validate_and_select(&policy(false), &request(), &second).unwrap();
        assert_eq!(
            first_selected.contributor_ids(),
            second_selected.contributor_ids()
        );
        assert_eq!(first_selected.contributor_ids(), vec!["a1", "a2"]);
    }

    #[test]
    fn duplicate_authorities_are_rejected() {
        let partials = vec![partial("a1", 1), partial("a1", 2), partial("a3", 3)];
        assert_eq!(
            validate_and_select(&policy(false), &request(), &partials),
            Err(DprfError::DuplicateAuthority("a1".to_owned()))
        );
    }

    #[test]
    fn organization_distinctness_changes_the_selected_set() {
        let partials = vec![partial("a1", 1), partial("a2", 2), partial("a3", 3)];
        let selected = validate_and_select(&policy(true), &request(), &partials).unwrap();
        assert_eq!(selected.contributor_ids(), vec!["a1", "a3"]);
    }

    #[test]
    fn stale_epoch_is_rejected() {
        let mut stale = partial("a1", 1);
        stale.epoch = 8;
        assert_eq!(
            validate_and_select(&policy(false), &request(), &[stale, partial("a3", 3)]),
            Err(DprfError::EpochMismatch)
        );
    }
}
