//! Generates and validates an epoch-one governance bundle for the VM lab.
//!
//! The checkpoint commits to the deployed key registries, LWR provisioning
//! manifest, independence model, clause catalog, and empty revocation state.
//! RPC observations are explicitly synthetic until a live IOTA deployment is
//! connected, so this utility does not support a live-ledger performance claim.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use anyhow::Context;
use astra_common::{Digest32, PROTOCOL_VERSION, hash_domain_separated};
use astra_governance::{
    GovernanceBundle, GovernanceCheckpoint, GovernanceKeySet, GovernanceProfile,
    GovernanceSignature, LedgerAnchor, LocalGovernanceState, RpcObservation, checkpoint_hash,
    governance_signature_message, validate_bundle,
};
use astra_pqcrypto::PqProvider;
use serde_json::json;
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const ROOT_LABEL: &[u8] = b"ASTRA-PQ-GOVERNANCE-ROOT-v1";
const TRANSACTION_LABEL: &[u8] = b"ASTRA-PQ-SYNTHETIC-IOTA-TRANSACTION-v1";
const MAXIMUM_AGE_SECONDS: u64 = 604_800;

fn main() -> anyhow::Result<()> {
    let output_root = PathBuf::from(required_environment("ASTRA_GOVERNANCE_OUTPUT")?);
    let authority_manifest = read_required_file("ASTRA_AUTHORITY_MANIFEST")?;
    let gateway_manifest = read_required_file("ASTRA_GATEWAY_MANIFEST")?;
    let lwr_manifest = read_required_file("ASTRA_LWR_MANIFEST")?;
    create_private_directory(&output_root)?;
    let actor_directory = output_root.join("actors");
    create_private_directory(&actor_directory)?;
    let now = unix_time()?;
    let activation_time = now.saturating_sub(1);
    anyhow::ensure!(activation_time > 0, "system clock is invalid");
    let provider = PqProvider::new().context("initialize post-quantum provider")?;

    let mut actor_public_keys = BTreeMap::new();
    let mut actor_secret_keys = Vec::new();
    for actor_number in 1..=2 {
        let actor_id = format!("gov-{actor_number}");
        let keypair = provider.generate_signature_keypair()?;
        let actor_path = actor_directory.join(&actor_id);
        create_private_directory(&actor_path)?;
        write_file(
            &actor_path.join("signing.sk"),
            keypair.secret_key().expose_secret(),
            0o600,
        )?;
        write_file(&actor_path.join("signing.pk"), keypair.public_key(), 0o644)?;
        actor_public_keys.insert(actor_id.clone(), keypair.public_key().to_vec());
        actor_secret_keys.push((actor_id, keypair));
    }

    let invocation_key = provider.generate_kem_keypair()?;
    let independence_model = br#"{"a1":"org-1","a2":"org-2","a3":"org-3","a4":"org-4","a5":"org-5","a6":"org-6","a7":"org-7"}"#;
    let clause_catalog = br#"{"profile":"exact-coalition-lab-v1","thresholds":[1,2,3,4,5,6,7],"adaptive_risk_mapping":{"R0":1,"R1":2,"R2":2,"R3":3,"R4":3}}"#;
    let revocation_state = br#"{"revoked_authorities":[],"revoked_gateways":[]}"#;
    let checkpoint = GovernanceCheckpoint {
        protocol_version: PROTOCOL_VERSION,
        epoch: 1,
        predecessor_hash: Digest32::from_bytes([0; 32]),
        epoch_randomness: root("epoch-randomness", &[invocation_key.public_key()]),
        registry_root: root("registry", &[&authority_manifest, &gateway_manifest]),
        independence_root: root("independence", &[independence_model]),
        policy_root: root("policy", &[clause_catalog]),
        revocation_root: root("revocation", &[revocation_state]),
        parameters_root: root("parameters", &[&lwr_manifest]),
        activation_time,
        maximum_age: MAXIMUM_AGE_SECONDS,
    };
    let checkpoint_digest = checkpoint_hash(&checkpoint)?;
    let profile = GovernanceProfile {
        network_id: "iota-lab-synthetic-observations".to_owned(),
        package_id: "0xastra-lab-package".to_owned(),
        object_id: "0xastra-governance-object".to_owned(),
        package_version: 1,
        rpc_quorum: 2,
    };
    let key_set = GovernanceKeySet {
        key_set_id: "astra-governance-actors-v1".to_owned(),
        threshold: 2,
        members: actor_public_keys,
    };
    let signature_message = governance_signature_message(
        &profile,
        &key_set.key_set_id,
        &checkpoint_digest,
        checkpoint.activation_time,
    )?;
    let signatures = actor_secret_keys
        .iter()
        .map(|(actor_id, keypair)| {
            Ok(GovernanceSignature {
                actor_id: actor_id.clone(),
                signature: provider.sign(keypair.secret_key(), &signature_message)?,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let transaction_digest = hash_domain_separated(
        TRANSACTION_LABEL,
        &[checkpoint_digest.as_bytes(), &now.to_be_bytes()],
    );
    let anchor = LedgerAnchor {
        network_id: profile.network_id.clone(),
        package_id: profile.package_id.clone(),
        object_id: profile.object_id.clone(),
        package_version: profile.package_version,
        epoch: checkpoint.epoch,
        predecessor_hash: checkpoint.predecessor_hash,
        checkpoint_hash: checkpoint_digest,
        activation_time: checkpoint.activation_time,
        object_version: 1,
        transaction_digest,
    };
    let observations = ["synthetic-rpc-1", "synthetic-rpc-2"]
        .into_iter()
        .map(|operator_id| RpcObservation {
            operator_id: operator_id.to_owned(),
            object_version: anchor.object_version,
            checkpoint_hash: checkpoint_digest,
            transaction_digest,
        })
        .collect();
    let bundle = GovernanceBundle {
        schema_version: 1,
        checkpoint,
        anchor,
        observations,
        profile,
        key_set,
        signatures,
    };
    let validated_state =
        validate_bundle(&provider, &LocalGovernanceState::default(), &bundle, now)
            .context("self-validate generated governance bundle")?;
    let bundle_path = output_root.join("governance-bundle.json");
    write_file(&bundle_path, &serde_json::to_vec_pretty(&bundle)?, 0o644)?;
    write_file(
        &output_root.join("validated-state.json"),
        &serde_json::to_vec_pretty(&validated_state)?,
        0o600,
    )?;
    let manifest = json!({
        "schema": "astra-pq-governance-provisioning-v1",
        "observation_mode": "synthetic-not-live-iota",
        "live_iota_claim": false,
        "checkpoint_hash": checkpoint_digest.to_string(),
        "epoch": bundle.checkpoint.epoch,
        "object_version": bundle.anchor.object_version,
        "rpc_quorum": bundle.profile.rpc_quorum,
        "governance_signature_threshold": bundle.key_set.threshold,
        "activation_time": bundle.checkpoint.activation_time,
        "maximum_age": bundle.checkpoint.maximum_age,
        "generated_at": now
    });
    write_file(
        &output_root.join("manifest.json"),
        &serde_json::to_vec_pretty(&manifest)?,
        0o644,
    )?;
    println!("{}", serde_json::to_string_pretty(&manifest)?);
    Ok(())
}

fn root(component: &str, parts: &[&[u8]]) -> Digest32 {
    let mut all_parts = Vec::with_capacity(parts.len() + 1);
    all_parts.push(component.as_bytes());
    all_parts.extend_from_slice(parts);
    hash_domain_separated(ROOT_LABEL, &all_parts)
}

fn read_required_file(environment_name: &str) -> anyhow::Result<Vec<u8>> {
    let path = PathBuf::from(required_environment(environment_name)?);
    fs::read(&path).with_context(|| format!("read {}", path.display()))
}

fn required_environment(name: &str) -> anyhow::Result<String> {
    let value = env::var(name).with_context(|| format!("missing {name}"))?;
    anyhow::ensure!(!value.trim().is_empty(), "{name} is empty");
    Ok(value)
}

fn unix_time() -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock precedes Unix epoch")?
        .as_secs())
}

fn create_private_directory(path: &Path) -> anyhow::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(path)
        .with_context(|| format!("create private directory {}", path.display()))
}

fn write_file(path: &Path, bytes: &[u8], mode: u32) -> anyhow::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .with_context(|| format!("create governance file {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
