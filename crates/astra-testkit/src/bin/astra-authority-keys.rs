//! Offline ML-DSA-65 key provisioner for the seven-node ASTRA-PQ lab.
//!
//! Private keys are written with owner-only permissions. Key files are not
//! encrypted, so distribution must use the authenticated SSH/Ansible
//! administration path and the authority service must perform a startup
//! sign-and-verify self-test against the paired public key.

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

const PUBLIC_KEY_HASH_LABEL: &[u8] = b"ASTRA-PQ-AUTHORITY-PUBLIC-KEY-v1";
const AUTHORITY_HOSTS: [&str; 7] = [
    "astra-domain-a",
    "astra-domain-b",
    "astra-authority-3",
    "astra-authority-4",
    "astra-authority-5",
    "astra-authority-6",
    "astra-authority-7",
];

fn main() -> anyhow::Result<()> {
    let output_root = required_output_root()?;
    create_private_directory(&output_root)
        .with_context(|| format!("create output directory {}", output_root.display()))?;
    let provider = PqProvider::new().context("initialize post-quantum provider")?;
    let metadata = provider.metadata();
    let mut authorities = Vec::new();

    for (index, host) in AUTHORITY_HOSTS.iter().enumerate() {
        let authority_number = index + 1;
        let authority_id = format!("a{authority_number}");
        let authority_directory = output_root.join(&authority_id);
        create_private_directory(&authority_directory)?;
        let keypair = provider
            .generate_signature_keypair()
            .with_context(|| format!("generate signing key for {authority_id}"))?;
        let secret_path = authority_directory.join("signing.sk");
        let public_path = authority_directory.join("signing.pk");
        write_file(&secret_path, keypair.secret_key().expose_secret(), 0o600)?;
        write_file(&public_path, keypair.public_key(), 0o644)?;
        let public_hash = hash_domain_separated(
            PUBLIC_KEY_HASH_LABEL,
            &[authority_id.as_bytes(), keypair.public_key()],
        );
        authorities.push(json!({
            "authority_id": authority_id,
            "host": host,
            "secret_key_relative_path": format!("a{authority_number}/signing.sk"),
            "public_key_relative_path": format!("a{authority_number}/signing.pk"),
            "secret_key_bytes": keypair.secret_key().len(),
            "public_key_bytes": keypair.public_key().len(),
            "public_key_hash": public_hash.to_string()
        }));
    }

    let manifest = json!({
        "schema": "astra-pq-authority-keys-v1",
        "lab_only": true,
        "encrypted_at_rest": false,
        "signature_algorithm": metadata.signature_algorithm,
        "signature_implementation": metadata.signature_implementation,
        "authorities": authorities
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
    let value = env::var("ASTRA_AUTHORITY_KEYS_OUTPUT")
        .context("ASTRA_AUTHORITY_KEYS_OUTPUT must name a new output directory")?;
    anyhow::ensure!(
        !value.trim().is_empty(),
        "authority-key output path is empty"
    );
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
