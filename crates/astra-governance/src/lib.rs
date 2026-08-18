//! Off-path governance checkpoint validation for ASTRA-PQ.
//!
//! This crate validates already-observed IOTA commitments. It is intentionally
//! absent from the real-time session authorization and key-derivation path.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use astra_common::{
    CanonicalEncode, Digest32, PROTOCOL_VERSION, ProtocolError, hash_domain_separated,
};
use astra_pqcrypto::{CryptoError, PqProvider};
use minicbor::Encoder;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const CHECKPOINT_LABEL: &[u8] = b"ASTRA-PQ-CHECKPOINT-v1";
const GOVERNANCE_SIGNATURE_LABEL: &[u8] = b"ASTRA-PQ-GOV-SIG-v1";
const MAX_TEXT_BYTES: usize = 512;

/// Governance checkpoint bundle committed by one epoch publication.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceCheckpoint {
    /// ASTRA-PQ protocol version.
    pub protocol_version: u16,
    /// Strictly increasing governance epoch.
    pub epoch: u64,
    /// Digest of the immediately preceding checkpoint, or zero for epoch one.
    pub predecessor_hash: Digest32,
    /// Epoch randomness used only where the governed policy permits it.
    pub epoch_randomness: Digest32,
    /// Authority identities and public-key registry root.
    pub registry_root: Digest32,
    /// Authority-independence classification root.
    pub independence_root: Digest32,
    /// Synthesis-policy and clause-catalog root.
    pub policy_root: Digest32,
    /// Revocation-state root.
    pub revocation_root: Digest32,
    /// DPRF public-parameter and share-version root.
    pub parameters_root: Digest32,
    /// Earliest Unix time at which this checkpoint may become active.
    pub activation_time: u64,
    /// Maximum cached use after local validation, in seconds.
    pub maximum_age: u64,
}

impl GovernanceCheckpoint {
    /// Validates bounded fields and hash-link shape.
    pub fn validate(&self) -> Result<(), GovernanceError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(GovernanceError::UnsupportedVersion(self.protocol_version));
        }
        if self.epoch == 0 || self.activation_time == 0 || self.maximum_age == 0 {
            return Err(GovernanceError::InvalidCheckpoint);
        }
        if self.epoch == 1 {
            if !self.predecessor_hash.is_zero() {
                return Err(GovernanceError::InvalidPredecessor);
            }
        } else if self.predecessor_hash.is_zero() {
            return Err(GovernanceError::InvalidPredecessor);
        }
        if [
            self.epoch_randomness,
            self.registry_root,
            self.independence_root,
            self.policy_root,
            self.revocation_root,
            self.parameters_root,
        ]
        .iter()
        .any(Digest32::is_zero)
        {
            return Err(GovernanceError::InvalidCheckpoint);
        }
        Ok(())
    }
}

impl CanonicalEncode for GovernanceCheckpoint {
    fn encode_canonical(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()
            .map_err(|error| ProtocolError::Encoding(error.to_string()))?;
        let mut bytes = Vec::new();
        let mut encoder = Encoder::new(&mut bytes);

        macro_rules! encode {
            ($operation:expr) => {
                $operation.map_err(|error| ProtocolError::Encoding(error.to_string()))?;
            };
        }

        encode!(encoder.map(11));
        encode!(encoder.u8(0));
        encode!(encoder.u16(self.protocol_version));
        encode!(encoder.u8(1));
        encode!(encoder.u64(self.epoch));
        encode!(encoder.u8(2));
        encode!(encoder.bytes(self.predecessor_hash.as_bytes()));
        encode!(encoder.u8(3));
        encode!(encoder.bytes(self.epoch_randomness.as_bytes()));
        encode!(encoder.u8(4));
        encode!(encoder.bytes(self.registry_root.as_bytes()));
        encode!(encoder.u8(5));
        encode!(encoder.bytes(self.independence_root.as_bytes()));
        encode!(encoder.u8(6));
        encode!(encoder.bytes(self.policy_root.as_bytes()));
        encode!(encoder.u8(7));
        encode!(encoder.bytes(self.revocation_root.as_bytes()));
        encode!(encoder.u8(8));
        encode!(encoder.bytes(self.parameters_root.as_bytes()));
        encode!(encoder.u8(9));
        encode!(encoder.u64(self.activation_time));
        encode!(encoder.u8(10));
        encode!(encoder.u64(self.maximum_age));
        Ok(bytes)
    }
}

/// IOTA shared-object commitment observed by synchronizers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerAnchor {
    /// IOTA network chain identifier.
    pub network_id: String,
    /// Deployed Move package identifier.
    pub package_id: String,
    /// Shared governance object identifier.
    pub object_id: String,
    /// Move package schema version.
    pub package_version: u64,
    /// Published governance epoch.
    pub epoch: u64,
    /// Published predecessor checkpoint digest.
    pub predecessor_hash: Digest32,
    /// Published checkpoint digest.
    pub checkpoint_hash: Digest32,
    /// Published activation time.
    pub activation_time: u64,
    /// Monotonic IOTA object version.
    pub object_version: u64,
    /// Transaction or network-checkpoint digest used for RPC agreement.
    pub transaction_digest: Digest32,
}

/// Independent full-node observation of an IOTA anchor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcObservation {
    /// Independently administered RPC operator identifier.
    pub operator_id: String,
    /// Observed IOTA object version.
    pub object_version: u64,
    /// Observed ASTRA-PQ checkpoint digest.
    pub checkpoint_hash: Digest32,
    /// Observed transaction or network-checkpoint digest.
    pub transaction_digest: Digest32,
}

/// Detached governance-actor signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceSignature {
    /// Governance actor identifier.
    pub actor_id: String,
    /// ML-DSA-65 signature bytes.
    pub signature: Vec<u8>,
}

/// Threshold verification-key set approved for an epoch transition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceKeySet {
    /// Stable governed key-set identifier.
    pub key_set_id: String,
    /// Number of distinct valid actor signatures required.
    pub threshold: u16,
    /// ML-DSA-65 public keys indexed by actor identifier.
    pub members: BTreeMap<String, Vec<u8>>,
}

/// Fixed deployment binding for the IOTA governance object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceProfile {
    /// Expected IOTA network identifier.
    pub network_id: String,
    /// Expected Move package identifier.
    pub package_id: String,
    /// Expected shared-object identifier.
    pub object_id: String,
    /// Expected package schema version.
    pub package_version: u64,
    /// Minimum number of independent agreeing RPC operators.
    pub rpc_quorum: u16,
}

/// Rollback-protected state that callers must persist crash-consistently.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalGovernanceState {
    /// Highest activated epoch, or zero before initial activation.
    pub highest_epoch: u64,
    /// Digest of the activated checkpoint.
    pub checkpoint_hash: Digest32,
    /// Local validation time in Unix seconds.
    pub validated_at: u64,
    /// IOTA object version corresponding to the activated checkpoint.
    pub object_version: u64,
}

impl Default for LocalGovernanceState {
    fn default() -> Self {
        Self {
            highest_epoch: 0,
            checkpoint_hash: Digest32::from_bytes([0; 32]),
            validated_at: 0,
            object_version: 0,
        }
    }
}

/// Complete candidate supplied to off-path checkpoint validation.
pub struct CheckpointCandidate<'a> {
    /// Current rollback-protected local state.
    pub current: &'a LocalGovernanceState,
    /// Downloaded and content-address-verified checkpoint bundle.
    pub checkpoint: &'a GovernanceCheckpoint,
    /// IOTA shared-object anchor.
    pub anchor: &'a LedgerAnchor,
    /// Observations from independently administered RPC endpoints.
    pub observations: &'a [RpcObservation],
    /// Configured IOTA deployment profile.
    pub profile: &'a GovernanceProfile,
    /// Configured governance ML-DSA key set.
    pub key_set: &'a GovernanceKeySet,
    /// Detached governance signatures.
    pub signatures: &'a [GovernanceSignature],
    /// Current trusted Unix time.
    pub now: u64,
}

/// Serializable off-path governance bundle distributed to protocol nodes.
///
/// The bundle contains public data only. Nodes must still validate every field,
/// RPC observation, transition, and governance signature before activation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceBundle {
    /// Bundle schema version.
    pub schema_version: u16,
    /// Downloaded governance checkpoint.
    pub checkpoint: GovernanceCheckpoint,
    /// IOTA shared-object anchor for the checkpoint.
    pub anchor: LedgerAnchor,
    /// Independently obtained full-node observations.
    pub observations: Vec<RpcObservation>,
    /// Expected IOTA deployment binding.
    pub profile: GovernanceProfile,
    /// Governance-actor verification-key set.
    pub key_set: GovernanceKeySet,
    /// Detached governance-actor signatures.
    pub signatures: Vec<GovernanceSignature>,
}

/// Validates and activates a serialized governance bundle off the session path.
pub fn validate_bundle(
    provider: &PqProvider,
    current: &LocalGovernanceState,
    bundle: &GovernanceBundle,
    now: u64,
) -> Result<LocalGovernanceState, GovernanceError> {
    if bundle.schema_version != 1 {
        return Err(GovernanceError::InvalidCheckpoint);
    }
    validate_and_activate(
        provider,
        CheckpointCandidate {
            current,
            checkpoint: &bundle.checkpoint,
            anchor: &bundle.anchor,
            observations: &bundle.observations,
            profile: &bundle.profile,
            key_set: &bundle.key_set,
            signatures: &bundle.signatures,
            now,
        },
    )
}

/// Computes the canonical checkpoint digest committed on IOTA.
pub fn checkpoint_hash(checkpoint: &GovernanceCheckpoint) -> Result<Digest32, GovernanceError> {
    let encoded = checkpoint.encode_canonical()?;
    Ok(hash_domain_separated(CHECKPOINT_LABEL, &[&encoded]))
}

/// Constructs the exact digest signed by detached governance actors.
pub fn governance_signature_message(
    profile: &GovernanceProfile,
    key_set_id: &str,
    checkpoint_digest: &Digest32,
    activation_time: u64,
) -> Result<Vec<u8>, GovernanceError> {
    validate_profile(profile)?;
    validate_text("key_set_id", key_set_id)?;
    let package_version = profile.package_version.to_be_bytes();
    let activation_time = activation_time.to_be_bytes();
    Ok(hash_domain_separated(
        GOVERNANCE_SIGNATURE_LABEL,
        &[
            profile.network_id.as_bytes(),
            profile.package_id.as_bytes(),
            profile.object_id.as_bytes(),
            &package_version,
            key_set_id.as_bytes(),
            checkpoint_digest.as_bytes(),
            &activation_time,
        ],
    )
    .as_bytes()
    .to_vec())
}

/// Validates and activates one strictly linked off-path checkpoint.
pub fn validate_and_activate(
    provider: &PqProvider,
    candidate: CheckpointCandidate<'_>,
) -> Result<LocalGovernanceState, GovernanceError> {
    candidate.checkpoint.validate()?;
    validate_profile(candidate.profile)?;
    validate_key_set(candidate.key_set)?;
    validate_anchor(candidate.profile, candidate.anchor)?;

    let digest = checkpoint_hash(candidate.checkpoint)?;
    if candidate.anchor.epoch != candidate.checkpoint.epoch
        || candidate.anchor.predecessor_hash != candidate.checkpoint.predecessor_hash
        || candidate.anchor.checkpoint_hash != digest
        || candidate.anchor.activation_time != candidate.checkpoint.activation_time
    {
        return Err(GovernanceError::AnchorMismatch);
    }
    if candidate.now < candidate.checkpoint.activation_time {
        return Err(GovernanceError::NotYetActive);
    }

    validate_transition(candidate.current, candidate.checkpoint, candidate.anchor)?;
    validate_rpc_quorum(
        candidate.profile.rpc_quorum,
        candidate.anchor,
        candidate.observations,
    )?;
    validate_governance_signatures(
        provider,
        candidate.profile,
        candidate.key_set,
        candidate.signatures,
        &digest,
        candidate.checkpoint.activation_time,
    )?;

    Ok(LocalGovernanceState {
        highest_epoch: candidate.checkpoint.epoch,
        checkpoint_hash: digest,
        validated_at: candidate.now,
        object_version: candidate.anchor.object_version,
    })
}

/// Returns whether the locally validated checkpoint remains usable off line.
#[must_use]
pub fn checkpoint_is_fresh(
    state: &LocalGovernanceState,
    checkpoint: &GovernanceCheckpoint,
    now: u64,
) -> bool {
    if state.highest_epoch != checkpoint.epoch || now < state.validated_at {
        return false;
    }
    let Ok(digest) = checkpoint_hash(checkpoint) else {
        return false;
    };
    state.checkpoint_hash == digest
        && now.saturating_sub(state.validated_at) <= checkpoint.maximum_age
}

fn validate_transition(
    current: &LocalGovernanceState,
    checkpoint: &GovernanceCheckpoint,
    anchor: &LedgerAnchor,
) -> Result<(), GovernanceError> {
    let expected_epoch = current
        .highest_epoch
        .checked_add(1)
        .ok_or(GovernanceError::RollbackOrGap)?;
    if checkpoint.epoch != expected_epoch {
        return Err(GovernanceError::RollbackOrGap);
    }
    if current.highest_epoch == 0 {
        if !checkpoint.predecessor_hash.is_zero() {
            return Err(GovernanceError::InvalidPredecessor);
        }
    } else if checkpoint.predecessor_hash != current.checkpoint_hash {
        return Err(GovernanceError::InvalidPredecessor);
    }
    if anchor.object_version <= current.object_version {
        return Err(GovernanceError::ObjectVersionRollback);
    }
    Ok(())
}

fn validate_rpc_quorum(
    required: u16,
    anchor: &LedgerAnchor,
    observations: &[RpcObservation],
) -> Result<(), GovernanceError> {
    let mut agreeing_operators = BTreeSet::new();
    for observation in observations {
        validate_text("rpc_operator_id", &observation.operator_id)?;
        if observation.object_version == anchor.object_version
            && observation.checkpoint_hash == anchor.checkpoint_hash
            && observation.transaction_digest == anchor.transaction_digest
        {
            agreeing_operators.insert(observation.operator_id.as_str());
        }
    }
    if agreeing_operators.len() < usize::from(required) {
        return Err(GovernanceError::InsufficientRpcAgreement {
            required,
            agreeing: agreeing_operators.len(),
        });
    }
    Ok(())
}

fn validate_governance_signatures(
    provider: &PqProvider,
    profile: &GovernanceProfile,
    key_set: &GovernanceKeySet,
    signatures: &[GovernanceSignature],
    digest: &Digest32,
    activation_time: u64,
) -> Result<(), GovernanceError> {
    let message =
        governance_signature_message(profile, &key_set.key_set_id, digest, activation_time)?;
    let mut valid_actors = BTreeSet::new();
    for signed in signatures {
        validate_text("governance_actor_id", &signed.actor_id)?;
        if valid_actors.contains(signed.actor_id.as_str()) {
            return Err(GovernanceError::DuplicateGovernanceSignature(
                signed.actor_id.clone(),
            ));
        }
        let public_key = key_set
            .members
            .get(&signed.actor_id)
            .ok_or_else(|| GovernanceError::UnknownGovernanceActor(signed.actor_id.clone()))?;
        provider.verify(public_key, &message, &signed.signature)?;
        valid_actors.insert(signed.actor_id.as_str());
    }
    if valid_actors.len() < usize::from(key_set.threshold) {
        return Err(GovernanceError::InsufficientGovernanceSignatures {
            required: key_set.threshold,
            valid: valid_actors.len(),
        });
    }
    Ok(())
}

fn validate_profile(profile: &GovernanceProfile) -> Result<(), GovernanceError> {
    validate_text("network_id", &profile.network_id)?;
    validate_text("package_id", &profile.package_id)?;
    validate_text("object_id", &profile.object_id)?;
    if profile.package_version == 0 || profile.rpc_quorum == 0 {
        return Err(GovernanceError::InvalidProfile);
    }
    Ok(())
}

fn validate_key_set(key_set: &GovernanceKeySet) -> Result<(), GovernanceError> {
    validate_text("key_set_id", &key_set.key_set_id)?;
    if key_set.threshold == 0 || key_set.members.len() < usize::from(key_set.threshold) {
        return Err(GovernanceError::InvalidKeySet);
    }
    for (actor, public_key) in &key_set.members {
        validate_text("governance_actor_id", actor)?;
        if public_key.is_empty() {
            return Err(GovernanceError::InvalidKeySet);
        }
    }
    Ok(())
}

fn validate_anchor(
    profile: &GovernanceProfile,
    anchor: &LedgerAnchor,
) -> Result<(), GovernanceError> {
    if anchor.network_id != profile.network_id
        || anchor.package_id != profile.package_id
        || anchor.object_id != profile.object_id
        || anchor.package_version != profile.package_version
        || anchor.object_version == 0
        || anchor.transaction_digest.is_zero()
    {
        return Err(GovernanceError::AnchorMismatch);
    }
    Ok(())
}

fn validate_text(field: &'static str, value: &str) -> Result<(), GovernanceError> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(GovernanceError::InvalidField(field));
    }
    Ok(())
}

/// Errors produced by off-path governance validation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum GovernanceError {
    /// The checkpoint protocol version is unsupported.
    #[error("unsupported governance protocol version {0}")]
    UnsupportedVersion(u16),
    /// A bounded identifier is malformed.
    #[error("invalid governance field: {0}")]
    InvalidField(&'static str),
    /// The checkpoint contains a zero or inconsistent required field.
    #[error("invalid governance checkpoint")]
    InvalidCheckpoint,
    /// The predecessor link is malformed or differs from local state.
    #[error("invalid checkpoint predecessor link")]
    InvalidPredecessor,
    /// The fixed deployment profile is invalid.
    #[error("invalid governance deployment profile")]
    InvalidProfile,
    /// The governance signature key set is invalid.
    #[error("invalid governance key set")]
    InvalidKeySet,
    /// Canonical checkpoint encoding failed.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    /// Post-quantum signature verification failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// The IOTA commitment differs from the bundle or deployment binding.
    #[error("IOTA anchor does not match the governance checkpoint")]
    AnchorMismatch,
    /// The checkpoint activation time is in the future.
    #[error("governance checkpoint is not yet active")]
    NotYetActive,
    /// The candidate is not the immediate monotonic successor.
    #[error("checkpoint rollback or epoch gap detected")]
    RollbackOrGap,
    /// The IOTA object version does not advance monotonically.
    #[error("IOTA governance object-version rollback detected")]
    ObjectVersionRollback,
    /// Too few independent RPC operators agree on the anchor.
    #[error("insufficient RPC agreement: required {required}, agreeing {agreeing}")]
    InsufficientRpcAgreement {
        /// Required agreeing operators.
        required: u16,
        /// Actual agreeing operators.
        agreeing: usize,
    },
    /// The same governance actor submitted multiple signatures.
    #[error("duplicate governance signature from {0}")]
    DuplicateGovernanceSignature(String),
    /// A signature names an actor outside the configured key set.
    #[error("unknown governance actor {0}")]
    UnknownGovernanceActor(String),
    /// Too few valid detached ML-DSA signatures were supplied.
    #[error("insufficient governance signatures: required {required}, valid {valid}")]
    InsufficientGovernanceSignatures {
        /// Required signatures.
        required: u16,
        /// Valid distinct signatures.
        valid: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checkpoint() -> GovernanceCheckpoint {
        GovernanceCheckpoint {
            protocol_version: PROTOCOL_VERSION,
            epoch: 1,
            predecessor_hash: Digest32::from_bytes([0; 32]),
            epoch_randomness: Digest32::from_bytes([1; 32]),
            registry_root: Digest32::from_bytes([2; 32]),
            independence_root: Digest32::from_bytes([3; 32]),
            policy_root: Digest32::from_bytes([4; 32]),
            revocation_root: Digest32::from_bytes([5; 32]),
            parameters_root: Digest32::from_bytes([6; 32]),
            activation_time: 1_700_000_000,
            maximum_age: 300,
        }
    }

    fn profile() -> GovernanceProfile {
        GovernanceProfile {
            network_id: "iota-testnet".to_owned(),
            package_id: "0xabc".to_owned(),
            object_id: "0xdef".to_owned(),
            package_version: 1,
            rpc_quorum: 2,
        }
    }

    #[test]
    fn threshold_signatures_and_rpc_quorum_activate_checkpoint() {
        let provider = PqProvider::new().unwrap();
        let actor_1 = provider.generate_signature_keypair().unwrap();
        let actor_2 = provider.generate_signature_keypair().unwrap();
        let checkpoint = checkpoint();
        let digest = checkpoint_hash(&checkpoint).unwrap();
        let profile = profile();
        let key_set = GovernanceKeySet {
            key_set_id: "governance-2026".to_owned(),
            threshold: 2,
            members: BTreeMap::from([
                ("actor-1".to_owned(), actor_1.public_key().to_vec()),
                ("actor-2".to_owned(), actor_2.public_key().to_vec()),
            ]),
        };
        let message = governance_signature_message(
            &profile,
            &key_set.key_set_id,
            &digest,
            checkpoint.activation_time,
        )
        .unwrap();
        let signatures = vec![
            GovernanceSignature {
                actor_id: "actor-1".to_owned(),
                signature: provider.sign(actor_1.secret_key(), &message).unwrap(),
            },
            GovernanceSignature {
                actor_id: "actor-2".to_owned(),
                signature: provider.sign(actor_2.secret_key(), &message).unwrap(),
            },
        ];
        let anchor = LedgerAnchor {
            network_id: profile.network_id.clone(),
            package_id: profile.package_id.clone(),
            object_id: profile.object_id.clone(),
            package_version: 1,
            epoch: 1,
            predecessor_hash: Digest32::from_bytes([0; 32]),
            checkpoint_hash: digest,
            activation_time: checkpoint.activation_time,
            object_version: 7,
            transaction_digest: Digest32::from_bytes([8; 32]),
        };
        let observations = vec![
            RpcObservation {
                operator_id: "rpc-a".to_owned(),
                object_version: 7,
                checkpoint_hash: digest,
                transaction_digest: Digest32::from_bytes([8; 32]),
            },
            RpcObservation {
                operator_id: "rpc-b".to_owned(),
                object_version: 7,
                checkpoint_hash: digest,
                transaction_digest: Digest32::from_bytes([8; 32]),
            },
        ];
        let state = validate_and_activate(
            &provider,
            CheckpointCandidate {
                current: &LocalGovernanceState::default(),
                checkpoint: &checkpoint,
                anchor: &anchor,
                observations: &observations,
                profile: &profile,
                key_set: &key_set,
                signatures: &signatures,
                now: checkpoint.activation_time + 10,
            },
        )
        .unwrap();
        assert_eq!(state.highest_epoch, 1);
        assert!(checkpoint_is_fresh(
            &state,
            &checkpoint,
            state.validated_at + 300
        ));
        assert!(!checkpoint_is_fresh(
            &state,
            &checkpoint,
            state.validated_at + 301
        ));
    }

    #[test]
    fn epoch_gap_is_rejected() {
        let mut candidate = checkpoint();
        candidate.epoch = 3;
        candidate.predecessor_hash = Digest32::from_bytes([9; 32]);
        let current = LocalGovernanceState {
            highest_epoch: 1,
            checkpoint_hash: Digest32::from_bytes([9; 32]),
            validated_at: 1,
            object_version: 2,
        };
        let anchor = LedgerAnchor {
            network_id: "iota-testnet".to_owned(),
            package_id: "0xabc".to_owned(),
            object_id: "0xdef".to_owned(),
            package_version: 1,
            epoch: 3,
            predecessor_hash: candidate.predecessor_hash,
            checkpoint_hash: checkpoint_hash(&candidate).unwrap(),
            activation_time: candidate.activation_time,
            object_version: 3,
            transaction_digest: Digest32::from_bytes([8; 32]),
        };
        assert_eq!(
            validate_transition(&current, &candidate, &anchor),
            Err(GovernanceError::RollbackOrGap)
        );
    }
}
