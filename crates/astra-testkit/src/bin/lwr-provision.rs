//! Offline lab provisioning utility for ASTRA-PQ LWR authority shares.
//!
//! This utility enumerates every exact coalition for thresholds one through
//! seven and creates a separate correlated LWR share set for each coalition.
//! Share files are created with owner-only permissions. The format detects
//! corruption but is not encrypted, so distribution must use an authenticated
//! administrative channel such as the lab's SSH/Ansible path.

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
const DEFAULT_MIN_THRESHOLD: usize = 1;
const DEFAULT_MAX_THRESHOLD: usize = 7;
const LAB_AUTHORITY_COUNT: usize = 7;
const SHARE_FILE_HASH_LABEL: &[u8] = b"ASTRA-PQ-LWR-SHARE-FILE-v1";

fn main() -> anyhow::Result<()> {
    let output_root = required_output_root()?;
    let minimum = environment_usize("ASTRA_PROVISION_MIN", DEFAULT_MIN_THRESHOLD)?;
    let maximum = environment_usize("ASTRA_PROVISION_MAX", DEFAULT_MAX_THRESHOLD)?;
    anyhow::ensure!(minimum >= 1, "minimum threshold must be at least one");
    anyhow::ensure!(maximum >= minimum, "maximum threshold is below minimum");
    anyhow::ensure!(
        maximum <= LAB_AUTHORITY_COUNT,
        "lab topology supports at most seven authorities"
    );

    create_private_directory(&output_root)
        .with_context(|| format!("create output directory {}", output_root.display()))?;
    let mut configurations = Vec::new();
    let mut total_share_files = 0_usize;
    let all_authorities: Vec<String> = (1..=LAB_AUTHORITY_COUNT)
        .map(|index| format!("a{index}"))
        .collect();

    for threshold in minimum..=maximum {
        let threshold_directory = output_root.join(format!("t{threshold}"));
        create_private_directory(&threshold_directory)?;
        for authorities in authority_combinations(&all_authorities, threshold) {
            let coalition_slug = authorities.join("-");
            let clause_id = format!("distributed-t{threshold}-c-{coalition_slug}");
            let coalition_directory = threshold_directory.join(&coalition_slug);
            create_private_directory(&coalition_directory)?;
            let shares = setup_exact_coalition(&clause_id, EPOCH, SHARE_VERSION, &authorities)
                .with_context(|| format!("generate exact coalition {coalition_slug}"))?;
            let mut share_records = Vec::new();

            for authority in &authorities {
                let share = shares
                    .get(authority)
                    .context("generated share map is incomplete")?;
                let encoded = share.export_lab_provisioning()?;
                let relative_path =
                    PathBuf::from(format!("t{threshold}/{coalition_slug}/{authority}.lwr"));
                let destination = output_root.join(&relative_path);
                write_owner_only(&destination, &encoded)?;
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

            configurations.push(json!({
                "threshold": threshold,
                "eligible_authorities": LAB_AUTHORITY_COUNT,
                "coalition_size": authorities.len(),
                "coalition_id": coalition_slug,
                "clause_id": clause_id,
                "epoch": EPOCH,
                "share_version": SHARE_VERSION,
                "authorities": authorities,
                "shares": share_records
            }));
        }
    }

    let manifest = json!({
        "schema": "astra-pq-lwr-enumerated-coalition-provisioning-v2",
        "lab_only": true,
        "encrypted_at_rest": false,
        "selection_model": "runtime selection among preprovisioned exact coalitions",
        "single_share_t_of_n": false,
        "integrity_mechanism": "SHAKE256 embedded checksum plus domain-separated SHA3-256 manifest hash",
        "authority_count": LAB_AUTHORITY_COUNT,
        "minimum_threshold": minimum,
        "maximum_threshold": maximum,
        "coalition_count": configurations.len(),
        "share_file_count": total_share_files,
        "configurations": configurations
    });
    let manifest_path = output_root.join("manifest.json");
    write_public_manifest(&manifest_path, &serde_json::to_vec_pretty(&manifest)?)?;
    println!("{}", serde_json::to_string_pretty(&manifest)?);
    Ok(())
}

fn authority_combinations(authorities: &[String], choose: usize) -> Vec<Vec<String>> {
    if choose == 0 || choose > authorities.len() {
        return Vec::new();
    }
    let mut combinations = Vec::new();
    let mut current = Vec::with_capacity(choose);
    collect_combinations(authorities, choose, 0, &mut current, &mut combinations);
    combinations
}

fn collect_combinations(
    authorities: &[String],
    choose: usize,
    start: usize,
    current: &mut Vec<String>,
    combinations: &mut Vec<Vec<String>>,
) {
    if current.len() == choose {
        combinations.push(current.clone());
        return;
    }
    let remaining = choose - current.len();
    let final_start = authorities.len() - remaining;
    for index in start..=final_start {
        current.push(authorities[index].clone());
        collect_combinations(authorities, choose, index + 1, current, combinations);
        current.pop();
    }
}

fn required_output_root() -> anyhow::Result<PathBuf> {
    let value = env::var("ASTRA_PROVISION_OUTPUT")
        .context("ASTRA_PROVISION_OUTPUT must name a new output directory")?;
    anyhow::ensure!(
        !value.trim().is_empty(),
        "provisioning output path is empty"
    );
    Ok(PathBuf::from(value))
}

fn environment_usize(name: &str, default: usize) -> anyhow::Result<usize> {
    match env::var(name) {
        Ok(value) => value
            .parse::<usize>()
            .with_context(|| format!("parse {name} as a positive integer")),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(error).with_context(|| format!("read {name}")),
    }
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
        .with_context(|| format!("create provisioning manifest {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seven_authorities_produce_all_nonempty_coalitions() {
        let authorities: Vec<String> = (1..=LAB_AUTHORITY_COUNT)
            .map(|index| format!("a{index}"))
            .collect();
        let counts: Vec<usize> = (1..=LAB_AUTHORITY_COUNT)
            .map(|threshold| authority_combinations(&authorities, threshold).len())
            .collect();
        assert_eq!(counts, vec![7, 21, 35, 35, 21, 7, 1]);
        assert_eq!(counts.iter().sum::<usize>(), 127);
        let share_count: usize = counts
            .iter()
            .enumerate()
            .map(|(index, count)| (index + 1) * count)
            .sum();
        assert_eq!(share_count, 448);
    }

    #[test]
    fn coalition_order_is_deterministic() {
        let authorities: Vec<String> = (1..=4).map(|index| format!("a{index}")).collect();
        assert_eq!(
            authority_combinations(&authorities, 2),
            vec![
                vec!["a1".to_owned(), "a2".to_owned()],
                vec!["a1".to_owned(), "a3".to_owned()],
                vec!["a1".to_owned(), "a4".to_owned()],
                vec!["a2".to_owned(), "a3".to_owned()],
                vec!["a2".to_owned(), "a4".to_owned()],
                vec!["a3".to_owned(), "a4".to_owned()],
            ]
        );
    }
}
