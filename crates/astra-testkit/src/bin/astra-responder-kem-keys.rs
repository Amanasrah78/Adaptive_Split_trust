//! Offline ML-KEM-768 responder-key provisioner for ASTRA-PQ Gateway B.
//!
//! The decapsulation key is role-separated from ML-DSA request-signing keys
//! and must be delivered only to the responder over the authenticated lab
//! administration channel.

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

const PUBLIC_KEY_HASH_LABEL: &[u8] = b"ASTRA-PQ-RESPONDER-KEM-PUBLIC-KEY-v1";
const RESPONDER_ID: &str = "gateway-b";
const RESPONDER_HOST: &str = "astra-domain-b";

fn main() -> anyhow::Result<()> {
    let output_root = required_output_root()?;
    create_private_directory(&output_root)
        .with_context(|| format!("create output directory {}", output_root.display()))?;

    let provider = PqProvider::new().context("initialize post-quantum provider")?;
    let metadata = provider.metadata();
    let keypair = provider
        .generate_kem_keypair()
        .context("generate Gateway B ML-KEM keypair")?;

    let startup_test = provider
        .encapsulate(keypair.public_key())
        .context("encapsulate responder-key self-test")?;
    let recovered = provider
        .decapsulate(keypair.secret_key(), startup_test.ciphertext())
        .context("decapsulate responder-key self-test")?;
    anyhow::ensure!(
        startup_test.shared_secret().expose_secret() == recovered.expose_secret(),
        "generated ML-KEM responder keypair failed self-test"
    );

    let secret_path = output_root.join("decapsulation.sk");
    let public_path = output_root.join("encapsulation.pk");
    write_file(&secret_path, keypair.secret_key().expose_secret(), 0o600)?;
    write_file(&public_path, keypair.public_key(), 0o644)?;
    let public_hash = hash_domain_separated(
        PUBLIC_KEY_HASH_LABEL,
        &[RESPONDER_ID.as_bytes(), keypair.public_key()],
    );

    let manifest = json!({
        "schema": "astra-pq-responder-kem-keys-v1",
        "lab_only": true,
        "encrypted_at_rest": false,
        "responder_id": RESPONDER_ID,
        "responder_host": RESPONDER_HOST,
        "role": "session-responder-decapsulation",
        "role_separated_from_request_signing": true,
        "kem_algorithm": metadata.kem_algorithm,
        "kem_implementation": metadata.kem_implementation,
        "kem_nist_level": metadata.kem_nist_level,
        "secret_key_relative_path": "decapsulation.sk",
        "public_key_relative_path": "encapsulation.pk",
        "secret_key_bytes": keypair.secret_key().len(),
        "public_key_bytes": keypair.public_key().len(),
        "public_key_hash": public_hash.to_string(),
        "generation_self_test": true
    });
    write_file(
        &output_root.join("manifest.json"),
        &serde_json::to_vec_pretty(&manifest)?,
        0o644,
    )?;
    println!("{}", serde_json::to_string_pretty(&manifest)?);
    Ok(())
}

fn required_output_root() -> anyhow::Result<PathBuf> {
    let value = env::var("ASTRA_RESPONDER_KEM_OUTPUT")
        .context("ASTRA_RESPONDER_KEM_OUTPUT must name a new output directory")?;
    anyhow::ensure!(
        !value.trim().is_empty(),
        "responder KEM output path is empty"
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
        .with_context(|| format!("create responder key file {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
