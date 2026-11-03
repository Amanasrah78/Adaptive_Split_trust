//! One-time adaptive LWR reprovisioning utility.
//!
//! Recreates the exact adaptive risk/clause topology from an existing
//! provisioning manifest while generating fresh LWR shares for the
//! currently configured session epoch and share version.

#![forbid(unsafe_code)]

use anyhow::{Context, anyhow};
use astra_common::hash_domain_separated;
use astra_dprf::lwr::setup_exact_coalition;
use astra_testkit::{SESSION_EPOCH, SESSION_SHARE_VERSION};
use serde_json::{Value, json};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const SHARE_FILE_HASH_LABEL: &[u8] = b"ASTRA-PQ-LWR-SHARE-FILE-v1";

fn main() -> anyhow::Result<()> {
    let template_path = PathBuf::from(
        env::var("ASTRA_ADAPTIVE_TEMPLATE").context("ASTRA_ADAPTIVE_TEMPLATE is required")?,
    );

    let output_root = PathBuf::from(
        env::var("ASTRA_ADAPTIVE_OUTPUT").context("ASTRA_ADAPTIVE_OUTPUT is required")?,
    );

    anyhow::ensure!(
        !output_root.exists(),
        "output directory already exists: {}",
        output_root.display()
    );

    create_private_directory(&output_root)?;

    let mut manifest: Value = serde_json::from_slice(
        &fs::read(&template_path).with_context(|| format!("read {}", template_path.display()))?,
    )
    .context("decode adaptive provisioning manifest")?;

    let risks = manifest
        .get_mut("risks")
        .and_then(Value::as_array_mut)
        .context("manifest has no risks array")?;

    let mut clause_count = 0usize;
    let mut share_count = 0usize;

    for risk in risks {
        let clauses = risk
            .get_mut("clauses")
            .and_then(Value::as_array_mut)
            .context("risk entry has no clauses array")?;

        for clause in clauses {
            let clause_id = clause
                .get("clause_id")
                .and_then(Value::as_str)
                .context("clause lacks clause_id")?
                .to_owned();

            let authorities = clause
                .get("authorities")
                .and_then(Value::as_array)
                .context("clause lacks authorities")?
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| anyhow!("authority identifier is not a string"))
                })
                .collect::<anyhow::Result<Vec<_>>>()?;

            anyhow::ensure!(
                !authorities.is_empty(),
                "clause {clause_id} has no authorities"
            );

            let generated = setup_exact_coalition(
                &clause_id,
                SESSION_EPOCH,
                SESSION_SHARE_VERSION,
                &authorities,
            )
            .with_context(|| format!("generate adaptive clause {clause_id}"))?;

            clause["epoch"] = json!(SESSION_EPOCH);
            clause["share_version"] = json!(SESSION_SHARE_VERSION);

            let records = clause
                .get_mut("shares")
                .and_then(Value::as_array_mut)
                .context("clause lacks share records")?;

            anyhow::ensure!(
                records.len() == authorities.len(),
                "share-record count differs from authority count for {clause_id}"
            );

            for record in records {
                let authority_id = record
                    .get("authority_id")
                    .and_then(Value::as_str)
                    .context("share record lacks authority_id")?
                    .to_owned();

                let relative_path = PathBuf::from(
                    record
                        .get("relative_path")
                        .and_then(Value::as_str)
                        .context("share record lacks relative_path")?,
                );

                let share = generated.get(&authority_id).with_context(|| {
                    format!("generated clause {clause_id} lacks authority {authority_id}")
                })?;

                let encoded = share.export_lab_provisioning().with_context(|| {
                    format!("export clause {clause_id} authority {authority_id}")
                })?;

                let destination = output_root.join(&relative_path);

                if let Some(parent) = destination.parent() {
                    create_private_directory(parent)?;
                }

                write_owner_only(&destination, &encoded)?;

                let digest = hash_domain_separated(SHARE_FILE_HASH_LABEL, &[encoded.as_ref()]);

                record["encoded_bytes"] = json!(encoded.len());
                record["secret_vector_bytes"] = json!(share.secret_size_bytes());
                record["file_hash"] = json!(digest.to_string());

                share_count += 1;
            }

            clause_count += 1;
        }
    }

    manifest["reprovisioned_epoch"] = json!(SESSION_EPOCH);
    manifest["reprovisioned_share_version"] = json!(SESSION_SHARE_VERSION);

    let manifest_path = output_root.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)
        .with_context(|| format!("write {}", manifest_path.display()))?;

    fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o644))?;

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "success": true,
            "template": template_path,
            "output": output_root,
            "epoch": SESSION_EPOCH,
            "share_version": SESSION_SHARE_VERSION,
            "clause_sets": clause_count,
            "share_files": share_count
        }))?
    );

    Ok(())
}

fn create_private_directory(path: &Path) -> anyhow::Result<()> {
    if path.exists() {
        anyhow::ensure!(
            path.is_dir(),
            "{} exists but is not a directory",
            path.display()
        );
        return Ok(());
    }

    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    builder.mode(0o700);
    builder
        .create(path)
        .with_context(|| format!("create {}", path.display()))
}

fn write_owner_only(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;

    file.write_all(bytes)?;
    file.flush()?;
    Ok(())
}
