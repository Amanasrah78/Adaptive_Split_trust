//! Prepares and finalizes live-IOTA ASTRA-PQ governance checkpoints.
//!
//! Preparation reuses an already validated checkpoint template and governance
//! key set, replaces the deployment binding with real IOTA identifiers, and
//! generates fresh detached ML-DSA signatures. Finalization converts a quorum-
//! agreed IOTA observation into the existing `GovernanceBundle` representation
//! and invokes the normative validator before writing local activation state.

#![forbid(unsafe_code)]

use anyhow::{Context, bail};
use astra_common::Digest32;
use astra_governance::{
    GovernanceBundle, GovernanceCheckpoint, GovernanceKeySet, GovernanceProfile,
    GovernanceSignature, LedgerAnchor, LocalGovernanceState, RpcObservation, checkpoint_hash,
    governance_signature_message, validate_bundle,
};
use astra_pqcrypto::PqProvider;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const PREPARED_SCHEMA: &str = "astra-pq-live-iota-prepared-checkpoint-v1";
const OBSERVATION_SCHEMA: &str = "astra-pq-live-iota-observation-v1";
const MAXIMUM_AGE_SECONDS: u64 = 604_800;

#[derive(Debug, Serialize, Deserialize)]
struct PreparedCheckpoint {
    schema: String,
    live_iota_claim: bool,
    generated_at_unix: u64,
    checkpoint_hash_hex: String,
    checkpoint: GovernanceCheckpoint,
    profile: GovernanceProfile,
    key_set: GovernanceKeySet,
    signatures: Vec<GovernanceSignature>,
}

#[derive(Debug, Deserialize)]
struct LiveObservation {
    schema: String,
    live_iota_claim: bool,
    agreement: Agreement,
    anchor: ObservedAnchor,
    observations: Vec<ObservedEndpoint>,
}

#[derive(Debug, Deserialize)]
struct Agreement {
    required: u16,
    agreeing: usize,
    operators: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ObservedAnchor {
    network_id: String,
    package_id: String,
    object_id: String,
    object_version: u64,
    previous_transaction: String,
    transaction_digest: String,
    package_version: u64,
    epoch: u64,
    predecessor_hash: String,
    checkpoint_hash: String,
    activation_time: u64,
    bundle_uri: String,
    governance_key_set_id: String,
}

#[derive(Debug, Deserialize)]
struct ObservedEndpoint {
    operator_id: String,
    network_id: String,
    package_id: String,
    object_id: String,
    object_version: u64,
    previous_transaction: String,
    transaction_digest: String,
    package_version: u64,
    epoch: u64,
    predecessor_hash: String,
    checkpoint_hash: String,
    activation_time: u64,
    bundle_uri: String,
    governance_key_set_id: String,
}

fn main() -> anyhow::Result<()> {
    match env::args().nth(1).as_deref() {
        Some("prepare") => prepare(),
        Some("finalize") => finalize(),
        _ => bail!("usage: astra-iota-governance <prepare|finalize>"),
    }
}

fn prepare() -> anyhow::Result<()> {
    let template_path = required_path("ASTRA_IOTA_TEMPLATE_BUNDLE")?;
    let actor_root = required_path("ASTRA_IOTA_ACTOR_SECRET_ROOT")?;
    let output_path = required_path("ASTRA_IOTA_PREPARED_OUTPUT")?;
    let network_id = required_environment("ASTRA_IOTA_NETWORK_ID")?;
    let package_id = required_environment("ASTRA_IOTA_PACKAGE_ID")?;
    let object_id = required_environment("ASTRA_IOTA_OBJECT_ID")?;
    let previous_state_path = env::var("ASTRA_IOTA_PREVIOUS_STATE")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from);
    let now = unix_time()?;

    let template: GovernanceBundle = read_json(&template_path)?;
    anyhow::ensure!(template.schema_version == 1, "unsupported template schema");

    let previous_state = match previous_state_path {
        Some(path) => Some(read_json::<LocalGovernanceState>(&path)?),
        None => None,
    };

    let mut checkpoint = template.checkpoint;

    match previous_state.as_ref() {
        Some(previous) => {
            checkpoint.epoch = previous
                .highest_epoch
                .checked_add(1)
                .context("governance epoch overflow")?;
            checkpoint.predecessor_hash = previous.checkpoint_hash;
        }
        None => {
            anyhow::ensure!(
                checkpoint.epoch == 1,
                "epoch-one preparation requires an epoch-one template"
            );
            anyhow::ensure!(
                checkpoint.predecessor_hash.is_zero(),
                "epoch-one template predecessor is not zero"
            );
        }
    }
    checkpoint.activation_time = now;
    checkpoint.maximum_age = MAXIMUM_AGE_SECONDS;
    checkpoint
        .validate()
        .context("validate prepared checkpoint")?;

    let profile = GovernanceProfile {
        network_id,
        package_id,
        object_id,
        package_version: 1,
        rpc_quorum: 2,
    };
    let key_set = template.key_set;
    let digest = checkpoint_hash(&checkpoint)?;
    let message = governance_signature_message(
        &profile,
        &key_set.key_set_id,
        &digest,
        checkpoint.activation_time,
    )?;
    let provider = PqProvider::new().context("initialize post-quantum provider")?;
    let mut signatures = Vec::with_capacity(key_set.members.len());
    for (actor_id, public_key) in &key_set.members {
        let secret_path = actor_root.join(actor_id).join("signing.sk");
        let metadata = fs::metadata(&secret_path)
            .with_context(|| format!("stat {}", secret_path.display()))?;
        anyhow::ensure!(metadata.is_file(), "actor secret is not a regular file");
        let secret = provider.import_signature_secret_key(
            fs::read(&secret_path).with_context(|| format!("read {}", secret_path.display()))?,
        )?;
        let signature = provider.sign(&secret, &message)?;
        provider
            .verify(public_key, &message, &signature)
            .with_context(|| format!("actor key mismatch for {actor_id}"))?;
        signatures.push(GovernanceSignature {
            actor_id: actor_id.clone(),
            signature,
        });
    }
    anyhow::ensure!(
        signatures.len() >= usize::from(key_set.threshold),
        "insufficient governance actor keys"
    );

    let prepared = PreparedCheckpoint {
        schema: PREPARED_SCHEMA.to_owned(),
        live_iota_claim: true,
        generated_at_unix: now,
        checkpoint_hash_hex: digest.to_string(),
        checkpoint,
        profile,
        key_set,
        signatures,
    };
    write_new_json(&output_path, &prepared, 0o644)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema": PREPARED_SCHEMA,
            "live_iota_claim": true,
            "epoch": prepared.checkpoint.epoch,
            "activation_time": prepared.checkpoint.activation_time,
            "maximum_age": prepared.checkpoint.maximum_age,
            "checkpoint_hash": prepared.checkpoint_hash_hex,
            "network_id": prepared.profile.network_id,
            "package_id": prepared.profile.package_id,
            "object_id": prepared.profile.object_id,
            "rpc_quorum": prepared.profile.rpc_quorum,
            "governance_key_set_id": prepared.key_set.key_set_id,
            "governance_signature_threshold": prepared.key_set.threshold,
            "governance_signatures": prepared.signatures.len(),
            "output": output_path,
        }))?
    );
    Ok(())
}

fn finalize() -> anyhow::Result<()> {
    let prepared_path = required_path("ASTRA_IOTA_PREPARED_CHECKPOINT")?;
    let observation_path = required_path("ASTRA_IOTA_LIVE_OBSERVATION")?;
    let bundle_output = required_path("ASTRA_IOTA_BUNDLE_OUTPUT")?;
    let state_output = required_path("ASTRA_IOTA_STATE_OUTPUT")?;
    let previous_state_path = env::var("ASTRA_IOTA_PREVIOUS_STATE")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from);
    let prepared: PreparedCheckpoint = read_json(&prepared_path)?;
    let observed: LiveObservation = read_json(&observation_path)?;
    anyhow::ensure!(
        prepared.schema == PREPARED_SCHEMA,
        "invalid prepared schema"
    );
    anyhow::ensure!(
        prepared.live_iota_claim,
        "prepared checkpoint is not live-IOTA"
    );
    anyhow::ensure!(
        observed.schema == OBSERVATION_SCHEMA,
        "invalid observation schema"
    );
    anyhow::ensure!(observed.live_iota_claim, "observation is not live-IOTA");
    anyhow::ensure!(
        observed.agreement.required == prepared.profile.rpc_quorum,
        "RPC quorum differs from the deployment profile"
    );
    anyhow::ensure!(
        observed.agreement.agreeing >= usize::from(prepared.profile.rpc_quorum),
        "insufficient agreeing observations"
    );
    anyhow::ensure!(
        observed.agreement.operators.len() == observed.agreement.agreeing,
        "operator agreement metadata is inconsistent"
    );

    let digest = checkpoint_hash(&prepared.checkpoint)?;
    anyhow::ensure!(
        prepared.checkpoint_hash_hex == digest.to_string(),
        "prepared checkpoint digest is inconsistent"
    );
    validate_observed_anchor(&prepared, &observed.anchor, &digest)?;
    anyhow::ensure!(
        observed.observations.len() >= usize::from(prepared.profile.rpc_quorum),
        "too few endpoint observations"
    );

    let transaction_digest = parse_digest32(&observed.anchor.transaction_digest)?;
    let mut rpc_observations = Vec::with_capacity(observed.observations.len());
    for endpoint in &observed.observations {
        validate_endpoint(endpoint, &observed.anchor)?;
        rpc_observations.push(RpcObservation {
            operator_id: endpoint.operator_id.clone(),
            object_version: endpoint.object_version,
            checkpoint_hash: digest,
            transaction_digest,
        });
    }
    let anchor = LedgerAnchor {
        network_id: prepared.profile.network_id.clone(),
        package_id: prepared.profile.package_id.clone(),
        object_id: prepared.profile.object_id.clone(),
        package_version: prepared.profile.package_version,
        epoch: prepared.checkpoint.epoch,
        predecessor_hash: prepared.checkpoint.predecessor_hash,
        checkpoint_hash: digest,
        activation_time: prepared.checkpoint.activation_time,
        object_version: observed.anchor.object_version,
        transaction_digest,
    };
    let bundle = GovernanceBundle {
        schema_version: 1,
        checkpoint: prepared.checkpoint,
        anchor,
        observations: rpc_observations,
        profile: prepared.profile,
        key_set: prepared.key_set,
        signatures: prepared.signatures,
    };
    let now = unix_time()?;
    let current_state = match previous_state_path {
        Some(path) => read_json::<LocalGovernanceState>(&path)?,
        None => LocalGovernanceState::default(),
    };
    let state = validate_bundle(
        &PqProvider::new().context("initialize post-quantum provider")?,
        &current_state,
        &bundle,
        now,
    )
    .context("validate live-IOTA governance bundle")?;
    write_new_json(&bundle_output, &bundle, 0o644)?;
    write_new_json(&state_output, &state, 0o600)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema": "astra-pq-live-iota-finalization-v1",
            "live_iota_claim": true,
            "validated": true,
            "epoch": state.highest_epoch,
            "checkpoint_hash": state.checkpoint_hash.to_string(),
            "object_version": state.object_version,
            "validated_at": state.validated_at,
            "iota_previous_transaction": observed.anchor.previous_transaction,
            "bundle_uri": observed.anchor.bundle_uri,
            "bundle_output": bundle_output,
            "state_output": state_output,
        }))?
    );
    Ok(())
}

fn validate_observed_anchor(
    prepared: &PreparedCheckpoint,
    anchor: &ObservedAnchor,
    digest: &Digest32,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        anchor.network_id == prepared.profile.network_id,
        "network mismatch"
    );
    anyhow::ensure!(
        anchor.package_id == prepared.profile.package_id,
        "package mismatch"
    );
    anyhow::ensure!(
        anchor.object_id == prepared.profile.object_id,
        "object mismatch"
    );
    anyhow::ensure!(
        anchor.package_version == prepared.profile.package_version,
        "package version mismatch"
    );
    anyhow::ensure!(anchor.epoch == prepared.checkpoint.epoch, "epoch mismatch");
    anyhow::ensure!(
        anchor.predecessor_hash == prepared.checkpoint.predecessor_hash.to_string(),
        "predecessor mismatch"
    );
    anyhow::ensure!(
        anchor.checkpoint_hash == digest.to_string(),
        "checkpoint mismatch"
    );
    anyhow::ensure!(
        anchor.activation_time == prepared.checkpoint.activation_time,
        "activation mismatch"
    );
    anyhow::ensure!(
        anchor.governance_key_set_id == prepared.key_set.key_set_id,
        "key-set mismatch"
    );
    anyhow::ensure!(anchor.object_version > 0, "invalid object version");
    anyhow::ensure!(!anchor.bundle_uri.is_empty(), "empty bundle URI");
    anyhow::ensure!(
        !anchor.previous_transaction.is_empty(),
        "empty IOTA transaction digest"
    );
    Ok(())
}

fn validate_endpoint(endpoint: &ObservedEndpoint, anchor: &ObservedAnchor) -> anyhow::Result<()> {
    anyhow::ensure!(
        endpoint.network_id == anchor.network_id,
        "endpoint network disagreement"
    );
    anyhow::ensure!(
        endpoint.package_id == anchor.package_id,
        "endpoint package disagreement"
    );
    anyhow::ensure!(
        endpoint.object_id == anchor.object_id,
        "endpoint object disagreement"
    );
    anyhow::ensure!(
        endpoint.object_version == anchor.object_version,
        "endpoint version disagreement"
    );
    anyhow::ensure!(
        endpoint.previous_transaction == anchor.previous_transaction,
        "endpoint transaction disagreement"
    );
    anyhow::ensure!(
        endpoint.transaction_digest == anchor.transaction_digest,
        "endpoint transaction mapping disagreement"
    );
    anyhow::ensure!(
        endpoint.package_version == anchor.package_version,
        "endpoint package-version disagreement"
    );
    anyhow::ensure!(
        endpoint.epoch == anchor.epoch,
        "endpoint epoch disagreement"
    );
    anyhow::ensure!(
        endpoint.predecessor_hash == anchor.predecessor_hash,
        "endpoint predecessor disagreement"
    );
    anyhow::ensure!(
        endpoint.checkpoint_hash == anchor.checkpoint_hash,
        "endpoint checkpoint disagreement"
    );
    anyhow::ensure!(
        endpoint.activation_time == anchor.activation_time,
        "endpoint activation disagreement"
    );
    anyhow::ensure!(
        endpoint.bundle_uri == anchor.bundle_uri,
        "endpoint URI disagreement"
    );
    anyhow::ensure!(
        endpoint.governance_key_set_id == anchor.governance_key_set_id,
        "endpoint key-set disagreement"
    );
    Ok(())
}

fn parse_digest32(value: &str) -> anyhow::Result<Digest32> {
    anyhow::ensure!(
        value.len() == 64,
        "digest must contain 64 hexadecimal characters"
    );
    let mut bytes = [0u8; 32];
    for (index, destination) in bytes.iter_mut().enumerate() {
        let offset = index * 2;
        *destination = u8::from_str_radix(&value[offset..offset + 2], 16)
            .context("digest contains non-hexadecimal characters")?;
    }
    Ok(Digest32::from_bytes(bytes))
}

fn required_environment(name: &str) -> anyhow::Result<String> {
    let value = env::var(name).with_context(|| format!("missing {name}"))?;
    anyhow::ensure!(!value.trim().is_empty(), "{name} is empty");
    Ok(value)
}

fn required_path(name: &str) -> anyhow::Result<PathBuf> {
    Ok(PathBuf::from(required_environment(name)?))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> anyhow::Result<T> {
    serde_json::from_slice(&fs::read(path).with_context(|| format!("read {}", path.display()))?)
        .with_context(|| format!("parse {}", path.display()))
}

fn write_new_json<T: Serialize>(path: &Path, value: &T, mode: u32) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn unix_time() -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock precedes Unix epoch")?
        .as_secs())
}
