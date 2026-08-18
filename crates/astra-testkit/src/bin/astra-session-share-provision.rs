//! Offline provisioning of clause-bound LWR shares for the ASTRA-PQ R3 session policy.
//!
//! This utility is intentionally separate from the threshold-scaling provisioner.
//! It creates the four exact-coalition share sets required by the canonical R3
//! policy: destination, risk floor, source, and safety.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use anyhow::Context;
use astra_common::hash_domain_separated;
use astra_dprf::lwr::setup_exact_coalition;
use serde_json::json;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const EPOCH: u64 = 1;
const SHARE_VERSION: u64 = 1;
const SHARE_FILE_HASH_LABEL: &[u8] = b"ASTRA-PQ-LWR-SHARE-FILE-v1";

struct ClauseSpecification {
    id: &'static str,
    purpose: &'static str,
    authorities: &'static [&'static str],
}

const CLAUSES: &[ClauseSpecification] = &[
    ClauseSpecification {
        id: "destination",
        purpose: "destination",
        authorities: &["a2"],
    },
    ClauseSpecification {
        id: "risk-floor",
        purpose: "risk-floor",
        authorities: &["a1", "a2", "a3"],
    },
    ClauseSpecification {
        id: "source",
        purpose: "source",
        authorities: &["a1"],
    },
    ClauseSpecification {
        id: "safety",
        purpose: "safety",
        authorities: &["a3"],
    },
];

fn main() -> anyhow::Result<()> {
    let output_root = required_output_root()?;
    create_private_directory(&output_root)
        .with_context(|| format!("create output directory {}", output_root.display()))?;

    let mut clause_records = Vec::new();
    let mut total_share_files = 0_usize;
    for specification in CLAUSES {
        let authorities = specification
            .authorities
            .iter()
            .map(|authority| (*authority).to_owned())
            .collect::<Vec<_>>();
        let clause_directory = output_root.join(specification.id);
        create_private_directory(&clause_directory)?;
        let shares = setup_exact_coalition(specification.id, EPOCH, SHARE_VERSION, &authorities)
            .with_context(|| format!("generate {} clause shares", specification.id))?;
        let mut share_records = Vec::new();

        for authority in &authorities {
            let share = shares
                .get(authority)
                .context("generated session share map is incomplete")?;
            let encoded = share.export_lab_provisioning()?;
            let relative_path = PathBuf::from(format!("{}/{}.lwr", specification.id, authority));
            let destination = output_root.join(&relative_path);
            write_owner_only(&destination, encoded.as_ref())?;
            let digest = hash_domain_separated(SHARE_FILE_HASH_LABEL, &[encoded.as_ref()]);
            share_records.push(json!({
                "authority_id": authority,
                "relative_path": relative_path,
                "encoded_bytes": encoded.len(),
                "secret_vector_bytes": share.secret_size_bytes(),
                "file_hash": digest.to_string()
            }));
            total_share_files += 1;
        }

        clause_records.push(json!({
            "clause_id": specification.id,
            "purpose": specification.purpose,
            "threshold": authorities.len(),
            "exact_coalition": true,
            "authorities": authorities,
            "epoch": EPOCH,
            "share_version": SHARE_VERSION,
            "shares": share_records
        }));
    }

    let manifest = json!({
        "schema": "astra-pq-r3-session-share-provisioning-v1",
        "lab_only": true,
        "risk_class": "R3",
        "encrypted_at_rest": false,
        "single_share_t_of_n": false,
        "security_profile": "post-quantum LWR; static corruption; semi-honest; exact coalition",
        "integrity_mechanism": "SHAKE256 embedded checksum plus domain-separated SHA3-256 manifest hash",
        "clause_count": clause_records.len(),
        "share_file_count": total_share_files,
        "clauses": clause_records
    });
    let manifest_path = output_root.join("manifest.json");
    write_public_manifest(&manifest_path, &serde_json::to_vec_pretty(&manifest)?)?;
    println!("{}", serde_json::to_string_pretty(&manifest)?);
    Ok(())
}

fn required_output_root() -> anyhow::Result<PathBuf> {
    let value = env::var("ASTRA_SESSION_SHARE_OUTPUT")
        .context("ASTRA_SESSION_SHARE_OUTPUT must name a new output directory")?;
    anyhow::ensure!(
        !value.trim().is_empty(),
        "session share output path is empty"
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

fn write_owner_only(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create owner-only share file {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn write_public_manifest(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut file = File::options()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create session share manifest {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r3_policy_has_the_expected_clause_coalitions() {
        let actual = CLAUSES
            .iter()
            .map(|clause| (clause.id, clause.authorities))
            .collect::<Vec<_>>();
        assert_eq!(
            actual,
            vec![
                ("destination", &["a2"][..]),
                ("risk-floor", &["a1", "a2", "a3"][..]),
                ("source", &["a1"][..]),
                ("safety", &["a3"][..]),
            ]
        );
        assert_eq!(
            CLAUSES
                .iter()
                .map(|clause| clause.authorities.len())
                .sum::<usize>(),
            6
        );
    }
}
