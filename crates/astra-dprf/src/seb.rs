//! Signature-gated, public signed-evidence binding (SEB) experiment.
//!
//! Not a DPRF and not a replacement for a reviewed LWR construction.
//! The authority signs the public participation digest in PartialEvaluation.
//! The gateway independently validates every authority signature and the
//! policy before invoking combine_authenticated with the original signatures.
//! The resulting binding value is PUBLIC, despite the Secret32 carrier type.

use crate::{
    ClausePolicy, DprfBackend, DprfError, EvaluationRequest, PartialEvaluation, validate_and_select,
};
use astra_common::{Secret32, hash_domain_separated};
use std::collections::BTreeMap;

const PARTICIPATION_LABEL: &[u8] = b"ASTRA-PQ-v1/SEB/participation";
const CLAUSE_LABEL: &[u8] = b"ASTRA-PQ-v1/SEB/signed-clause";

/// Experimental, explicit deployment-wide authorization mechanism selector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizationMode {
    /// Existing, unchanged exact-coalition LWR backend.
    Lwr,
    /// Public, signature-gated participation binding, without LWR shares.
    Seb,
}

impl AuthorizationMode {
    /// Reject unknown mechanism identifiers instead of silently downgrading.
    pub fn parse(value: &str) -> Result<Self, DprfError> {
        match value {
            "lwr" => Ok(Self::Lwr),
            "seb" => Ok(Self::Seb),
            _ => Err(DprfError::InvalidField("authorization_mode")),
        }
    }

    /// Stable experimental mechanism label, used in logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lwr => "lwr",
            Self::Seb => "seb",
        }
    }
}

/// Signature-only authorization-binding control, not a DPRF.
#[derive(Clone, Copy, Debug, Default)]
pub struct SignedEvidenceBindingBackend;

fn participation_digest(authority_id: &str, request: &EvaluationRequest) -> [u8; 32] {
    let epoch = request.epoch.to_be_bytes();
    let version = request.share_version.to_be_bytes();
    *hash_domain_separated(
        PARTICIPATION_LABEL,
        &[
            authority_id.as_bytes(),
            request.clause_id.as_bytes(),
            &epoch,
            &version,
            request.input.as_bytes(),
        ],
    )
    .as_bytes()
}

impl DprfBackend for SignedEvidenceBindingBackend {
    // ABI compatibility only: no key or cryptographic share is provisioned.
    type Share = [u8; 32];

    fn backend_id(&self) -> &'static str {
        "signed-evidence-binding-v1"
    }

    fn partial_evaluate(
        &self,
        authority_id: &str,
        _unused: &Self::Share,
        request: &EvaluationRequest,
    ) -> Result<PartialEvaluation, DprfError> {
        request.validate()?;
        if authority_id.is_empty()
            || authority_id.len() > 256
            || authority_id.chars().any(char::is_control)
        {
            return Err(DprfError::InvalidField("authority_id"));
        }
        Ok(PartialEvaluation {
            authority_id: authority_id.to_owned(),
            clause_id: request.clause_id.clone(),
            epoch: request.epoch,
            share_version: request.share_version,
            input: request.input,
            payload: participation_digest(authority_id, request).to_vec(),
            proof: Vec::new(),
        })
    }

    // Deliberately not usable without authenticated, original signature bytes.
    fn combine(
        &self,
        _policy: &ClausePolicy,
        _request: &EvaluationRequest,
        _partials: &[PartialEvaluation],
    ) -> Result<Secret32, DprfError> {
        Err(DprfError::MissingAuthenticatedEvidence("seb".to_owned()))
    }

    fn combine_authenticated(
        &self,
        policy: &ClausePolicy,
        request: &EvaluationRequest,
        partials: &[PartialEvaluation],
        signatures: &[(&str, &[u8])],
    ) -> Result<Secret32, DprfError> {
        // Selection is identical to the LWR arm. The gateway has already
        // verified each item's ML-DSA signature, policy hash and context.
        let selected = validate_and_select(policy, request, partials)?;
        let mut indexed = BTreeMap::<&str, &[u8]>::new();
        for (id, signature) in signatures {
            if signature.is_empty() || indexed.insert(*id, *signature).is_some() {
                return Err(DprfError::MissingAuthenticatedEvidence((*id).to_owned()));
            }
        }
        let epoch = request.epoch.to_be_bytes();
        let version = request.share_version.to_be_bytes();
        let threshold = policy.threshold.to_be_bytes();
        let mut fields = vec![
            policy.clause_id.as_bytes().to_vec(),
            epoch.to_vec(),
            version.to_vec(),
            request.input.as_bytes().to_vec(),
            threshold.to_vec(),
        ];
        for partial in selected.partials() {
            let expected = participation_digest(&partial.authority_id, request);
            if !partial.proof.is_empty() || partial.payload.as_slice() != expected.as_slice() {
                return Err(DprfError::InvalidParticipationDigest);
            }
            let signature = indexed.get(partial.authority_id.as_str()).ok_or_else(|| {
                DprfError::MissingAuthenticatedEvidence(partial.authority_id.clone())
            })?;
            fields.push(partial.authority_id.as_bytes().to_vec());
            fields.push(partial.payload.clone());
            fields.push(signature.to_vec());
        }
        let fields_as_slices: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
        let digest = hash_domain_separated(CLAUSE_LABEL, &fields_as_slices);
        Ok(Secret32::from_bytes(*digest.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astra_common::Digest32;

    fn policy() -> ClausePolicy {
        ClausePolicy {
            clause_id: "risk-floor".to_owned(),
            threshold: 2,
            members: BTreeMap::from([
                ("a1".to_owned(), "org1".to_owned()),
                ("a2".to_owned(), "org2".to_owned()),
                ("a3".to_owned(), "org1".to_owned()),
            ]),
            require_distinct_organizations: true,
        }
    }
    fn request() -> EvaluationRequest {
        EvaluationRequest {
            clause_id: "risk-floor".to_owned(),
            epoch: 2,
            share_version: 1,
            input: Digest32::from_bytes([9; 32]),
        }
    }
    fn partials(request: &EvaluationRequest) -> Vec<PartialEvaluation> {
        let b = SignedEvidenceBindingBackend;
        vec![
            b.partial_evaluate("a1", &[0; 32], request).unwrap(),
            b.partial_evaluate("a2", &[0; 32], request).unwrap(),
        ]
    }
    fn signatures<'a>() -> [(&'a str, &'a [u8]); 2] {
        [("a1", b"verified-sig-a1"), ("a2", b"verified-sig-a2")]
    }

    #[test]
    fn mechanism_parser_is_fail_closed() {
        assert_eq!(
            AuthorizationMode::parse("lwr").unwrap(),
            AuthorizationMode::Lwr
        );
        assert_eq!(
            AuthorizationMode::parse("seb").unwrap(),
            AuthorizationMode::Seb
        );
        assert!(AuthorizationMode::parse("unknown").is_err());
    }

    #[test]
    fn missing_authority_and_same_organization_fail() {
        let b = SignedEvidenceBindingBackend;
        let r = request();
        let a1 = b.partial_evaluate("a1", &[0; 32], &r).unwrap();
        let a3 = b.partial_evaluate("a3", &[0; 32], &r).unwrap();
        assert!(
            b.combine_authenticated(&policy(), &r, &[a1.clone()], &signatures())
                .is_err()
        );
        assert!(
            b.combine_authenticated(&policy(), &r, &[a1, a3], &signatures())
                .is_err()
        );
    }

    #[test]
    fn authenticated_signatures_and_input_bind_final_value() {
        let b = SignedEvidenceBindingBackend;
        let r = request();
        let p = partials(&r);
        let a = b
            .combine_authenticated(&policy(), &r, &p, &signatures())
            .unwrap();
        let changed_sig = [
            ("a1", &b"verified-sig-x"[..]),
            ("a2", &b"verified-sig-a2"[..]),
        ];
        let b_sig = b
            .combine_authenticated(&policy(), &r, &p, &changed_sig)
            .unwrap();
        assert_ne!(a.expose_secret(), b_sig.expose_secret());
        let mut r2 = r.clone();
        r2.input = Digest32::from_bytes([8; 32]);
        let b_input = b
            .combine_authenticated(&policy(), &r2, &partials(&r2), &signatures())
            .unwrap();
        assert_ne!(a.expose_secret(), b_input.expose_secret());
        assert!(b.combine(&policy(), &r, &p).is_err());
    }

    #[test]
    fn altered_participation_digest_and_missing_signature_fail() {
        let b = SignedEvidenceBindingBackend;
        let r = request();
        let mut p = partials(&r);
        p[0].payload[0] ^= 1;
        assert_eq!(
            b.combine_authenticated(&policy(), &r, &p, &signatures())
                .unwrap_err(),
            DprfError::InvalidParticipationDigest
        );
        let correct = partials(&r);
        assert!(
            b.combine_authenticated(&policy(), &r, &correct, &[("a1", b"signed")])
                .is_err()
        );
        let mut lwr = correct;
        lwr[0].payload = vec![0; 208];
        assert!(
            b.combine_authenticated(&policy(), &r, &lwr, &signatures())
                .is_err()
        );
    }
}
