//! Offline ML-DSA-65 request-signing key provisioner for ASTRA-PQ gateways.
//!
//! Gateway keys are distinct from authority evidence-signing keys. Private
//! files use owner-only permissions and must be distributed over the lab's
//! authenticated SSH/Ansible administration path.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use anyhow::Context;
use astra_common::hash_domain_separated;
use astra_pqcrypto::PqProvider;
use serde_json::json;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const PUBLIC_KEY_HASH_LABEL: &[u8] = b"ASTRA-PQ-GATEWAY-PUBLIC-KEY-v1";
const GATEWAYS: [(&str, &str); 2] = [
    ("gateway-a", "astra-domain-a"),
    ("gateway-b", "astra-domain-b"),
];

fn main() -> anyhow::Result<()> {
    let output_root = required_output_root()?;
    create_private_directory(&output_root)
        .with_context(|| format!("create output directory {}", output_root.display()))?;
    let provider = PqProvider::new().context("initialize post-quantum provider")?;
    let metadata = provider.metadata();
    let mut gateways = Vec::new();

    for (gateway_id, host) in GATEWAYS {
        let gateway_directory = output_root.join(gateway_id);
        create_private_directory(&gateway_directory)?;
        let keypair = provider
            .generate_signature_keypair()
            .with_context(|| format!("generate request-signing key for {gateway_id}"))?;
        let secret_path = gateway_directory.join("request-signing.sk");
        let public_path = gateway_directory.join("request-signing.pk");
        write_file(&secret_path, keypair.secret_key().expose_secret(), 0o600)?;
        write_file(&public_path, keypair.public_key(), 0o644)?;
        let public_hash = hash_domain_separated(
            PUBLIC_KEY_HASH_LABEL,
            &[gateway_id.as_bytes(), keypair.public_key()],
        );
        gateways.push(json!({
            "gateway_id": gateway_id,
            "host": host,
            "secret_key_relative_path": format!("{gateway_id}/request-signing.sk"),
            "public_key_relative_path": format!("{gateway_id}/request-signing.pk"),
            "secret_key_bytes": keypair.secret_key().len(),
            "public_key_bytes": keypair.public_key().len(),
            "public_key_hash": public_hash.to_string()
        }));
    }

    let manifest = json!({
        "schema": "astra-pq-gateway-keys-v1",
        "lab_only": true,
        "encrypted_at_rest": false,
        "role_separated_from_authority_keys": true,
        "signature_algorithm": metadata.signature_algorithm,
        "signature_implementation": metadata.signature_implementation,
        "gateways": gateways
    });
    let manifest_path = output_root.join("manifest.json");
    write_file(
        &manifest_path,
        &serde_json::to_vec_pretty(&manifest)?,
        0o644,
    )?;
    println!("{}", serde_json::to_string_pretty(&manifest)?);
    Ok(())
}

fn required_output_root() -> anyhow::Result<PathBuf> {
    let value = env::var("ASTRA_GATEWAY_KEYS_OUTPUT")
        .context("ASTRA_GATEWAY_KEYS_OUTPUT must name a new output directory")?;
    anyhow::ensure!(!value.trim().is_empty(), "gateway-key output path is empty");
    Ok(PathBuf::from(value))
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
        .with_context(|| format!("create key file {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
