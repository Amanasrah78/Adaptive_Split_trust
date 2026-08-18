//! Offline provisioning of risk-qualified LWR shares for ASTRA-PQ sessions.
//!
//! The utility creates exact-coalition share sets for every governed lab
//! policy from R0 through R4. Shares remain bound to their normative clause
//! identifier, while the directory path supplies the risk-qualified storage
//! namespace consumed by the authority service.

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

struct RiskSpecification {
    id: &'static str,
    synthesizer_floor: u16,
    governed_floor: u16,
    clauses: &'static [ClauseSpecification],
}

const R0_CLAUSES: &[ClauseSpecification] = &[ClauseSpecification {
    id: "destination",
    purpose: "destination",
    authorities: &["a2"],
}];

const R1_CLAUSES: &[ClauseSpecification] = &[
    ClauseSpecification {
        id: "destination",
        purpose: "destination",
        authorities: &["a2"],
    },
    ClauseSpecification {
        id: "risk-floor",
        purpose: "risk-floor",
        authorities: &["a1", "a2"],
    },
];

const R2_CLAUSES: &[ClauseSpecification] = &[
    ClauseSpecification {
        id: "destination",
        purpose: "destination",
        authorities: &["a2"],
    },
    ClauseSpecification {
        id: "risk-floor",
        purpose: "risk-floor",
        authorities: &["a1", "a2"],
    },
    ClauseSpecification {
        id: "source-or-oversight",
        purpose: "source-or-oversight",
        authorities: &["a1"],
    },
];

const R3_CLAUSES: &[ClauseSpecification] = &[
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

const R4_CLAUSES: &[ClauseSpecification] = &[
    ClauseSpecification {
        id: "destination",
        purpose: "destination",
        authorities: &["a2"],
    },
    ClauseSpecification {
        id: "risk-floor",
        purpose: "risk-floor",
        authorities: &["a1", "a2", "a3", "a4"],
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
    ClauseSpecification {
        id: "human-confirmation",
        purpose: "human-confirmation",
        authorities: &["a4"],
    },
];

const RISKS: &[RiskSpecification] = &[
    RiskSpecification {
        id: "r0",
        synthesizer_floor: 1,
        governed_floor: 1,
        clauses: R0_CLAUSES,
    },
    RiskSpecification {
        id: "r1",
        synthesizer_floor: 2,
        governed_floor: 2,
        clauses: R1_CLAUSES,
    },
    RiskSpecification {
        id: "r2",
        synthesizer_floor: 2,
        governed_floor: 2,
        clauses: R2_CLAUSES,
    },
    RiskSpecification {
        id: "r3",
        synthesizer_floor: 3,
        governed_floor: 3,
        clauses: R3_CLAUSES,
    },
    RiskSpecification {
        id: "r4",
        synthesizer_floor: 3,
        governed_floor: 4,
        clauses: R4_CLAUSES,
    },
];

fn main() -> anyhow::Result<()> {
    let output_root = required_output_root()?;
    create_private_directory(&output_root)
        .with_context(|| format!("create output directory {}", output_root.display()))?;

    let mut risk_records = Vec::new();
    let mut total_clause_sets = 0_usize;
    let mut total_share_files = 0_usize;

    for risk in RISKS {
        let mut clause_records = Vec::new();
        for specification in risk.clauses {
            let authorities = specification
                .authorities
                .iter()
                .map(|authority| (*authority).to_owned())
                .collect::<Vec<_>>();
            let clause_directory = output_root.join(risk.id).join(specification.id);
            create_private_directory(&clause_directory)?;
            let shares =
                setup_exact_coalition(specification.id, EPOCH, SHARE_VERSION, &authorities)
                    .with_context(|| {
                        format!("generate {} {} clause shares", risk.id, specification.id)
                    })?;
            let mut share_records = Vec::new();

            for authority in &authorities {
                let share = shares
                    .get(authority)
                    .context("generated adaptive session share map is incomplete")?;
                let encoded = share.export_lab_provisioning()?;
                let relative_path = PathBuf::from(format!(
                    "{}/{}/{}.lwr",
                    risk.id, specification.id, authority
                ));
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
            total_clause_sets += 1;
        }

        risk_records.push(json!({
            "risk_class": risk.id.to_ascii_uppercase(),
            "directory": risk.id,
            "synthesizer_minimum_authorities": risk.synthesizer_floor,
            "governed_minimum_organizations": risk.governed_floor,
            "governed_floor_override": risk.governed_floor > risk.synthesizer_floor,
            "clause_count": risk.clauses.len(),
            "evidence_count": risk
                .clauses
                .iter()
                .map(|clause| clause.authorities.len())
                .sum::<usize>(),
            "clauses": clause_records
        }));
    }

    let manifest = json!({
        "schema": "astra-pq-adaptive-session-share-provisioning-v2",
        "lab_only": true,
        "risk_classes": ["R0", "R1", "R2", "R3", "R4"],
        "encrypted_at_rest": false,
        "single_share_t_of_n": false,
        "selection_model": "risk-qualified exact coalitions",
        "security_profile": "post-quantum LWR; static corruption; semi-honest; exact coalition",
        "integrity_mechanism": "SHAKE256 embedded checksum plus domain-separated SHA3-256 manifest hash",
        "clause_set_count": total_clause_sets,
        "share_file_count": total_share_files,
        "risks": risk_records
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
    fn adaptive_policy_sizes_match_the_governed_model() {
        let actual = RISKS
            .iter()
            .map(|risk| {
                (
                    risk.id,
                    risk.clauses.len(),
                    risk.clauses
                        .iter()
                        .map(|clause| clause.authorities.len())
                        .sum::<usize>(),
                    risk.governed_floor,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            actual,
            vec![
                ("r0", 1, 1, 1),
                ("r1", 2, 3, 2),
                ("r2", 3, 4, 2),
                ("r3", 4, 6, 3),
                ("r4", 5, 8, 4),
            ]
        );
        assert_eq!(
            RISKS.iter().map(|risk| risk.clauses.len()).sum::<usize>(),
            15
        );
        assert_eq!(
            RISKS
                .iter()
                .flat_map(|risk| risk.clauses)
                .map(|clause| clause.authorities.len())
                .sum::<usize>(),
            22
        );
    }

    #[test]
    fn r4_adds_independent_human_confirmation() {
        let r4 = RISKS.iter().find(|risk| risk.id == "r4").unwrap();
        let human = r4
            .clauses
            .iter()
            .find(|clause| clause.id == "human-confirmation")
            .unwrap();
        assert_eq!(human.authorities, &["a4"]);
        assert_eq!(r4.synthesizer_floor, 3);
        assert_eq!(r4.governed_floor, 4);
    }
}
