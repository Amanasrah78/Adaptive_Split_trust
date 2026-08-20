//! Logical policy-synthesis scaling benchmark for ASTRA-PQ.
//!
//! This benchmark varies the number of governance records, risk class, and
//! additional governed roles. It measures deterministic local synthesis only;
//! it does not provision or contact the corresponding authority population.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use anyhow::Context;
use astra_common::{
    CanonicalEncode, Digest32, PROTOCOL_VERSION, RiskClass, SessionContext, SessionId,
};
use astra_synthesizer::{AuthorityRecord, SynthesisRequest, synthesize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::env;
use std::hint::black_box;
use std::time::Instant;

const EPOCH: u64 = 1;
const DEFAULT_REPETITIONS: usize = 100;
const DEFAULT_WARMUP_ITERATIONS: usize = 20;
const POPULATIONS: &[usize] = &[3, 4, 5, 7, 10, 20, 50];
const ADDITIONAL_ROLE_COUNTS: &[usize] = &[0, 2, 4, 8];
const RISKS: &[RiskClass] = &[
    RiskClass::R0,
    RiskClass::R1,
    RiskClass::R2,
    RiskClass::R3,
    RiskClass::R4,
];

fn main() -> anyhow::Result<()> {
    let repetitions = environment_usize("ASTRA_SYNTHESIS_REPETITIONS", DEFAULT_REPETITIONS)?;
    let warmup_iterations = environment_usize(
        "ASTRA_SYNTHESIS_WARMUP_ITERATIONS",
        DEFAULT_WARMUP_ITERATIONS,
    )?;
    anyhow::ensure!(repetitions >= 1, "repetitions must be at least one");

    for &population in POPULATIONS {
        for &risk in RISKS {
            for &additional_role_count in ADDITIONAL_ROLE_COUNTS {
                let (authorities, required_roles) =
                    generated_registry(population, additional_role_count)?;

                for warmup in 1..=warmup_iterations {
                    black_box(measure_synthesis(
                        population,
                        risk,
                        additional_role_count,
                        warmup,
                        &authorities,
                        &required_roles,
                    )?);
                }

                for run in 1..=repetitions {
                    let report = measure_synthesis(
                        population,
                        risk,
                        additional_role_count,
                        run,
                        &authorities,
                        &required_roles,
                    )?;
                    println!("{}", serde_json::to_string(&report)?);
                }
            }
        }
    }
    Ok(())
}

fn measure_synthesis(
    population: usize,
    risk: RiskClass,
    additional_role_count: usize,
    run: usize,
    authorities: &[AuthorityRecord],
    required_roles: &BTreeSet<String>,
) -> anyhow::Result<Value> {
    let request = SynthesisRequest {
        context: benchmark_context(population, risk, additional_role_count, run),
        authorities: authorities.to_vec(),
        required_roles: required_roles.clone(),
        minimum_organizations: governed_minimum_organizations(risk),
    };

    let start = Instant::now();
    let result = synthesize(black_box(&request));
    let synthesis_ns = start.elapsed().as_nanos();

    match result {
        Ok(result) => {
            let encoded = result
                .structure
                .encode_canonical()
                .context("encode synthesized policy")?;
            let clause_count = result.structure.clauses.len();
            let evidence_count = result
                .structure
                .clauses
                .iter()
                .map(|clause| usize::from(clause.threshold))
                .sum::<usize>();
            let clause_member_references = result
                .structure
                .clauses
                .iter()
                .map(|clause| clause.members.len())
                .sum::<usize>();
            let maximum_clause_members = result
                .structure
                .clauses
                .iter()
                .map(|clause| clause.members.len())
                .max()
                .unwrap_or(0);
            let exact_clause_count = result
                .structure
                .clauses
                .iter()
                .filter(|clause| clause.members.len() == usize::from(clause.threshold))
                .count();

            Ok(json!({
                "schema": "astra-pq-synthesis-scale-v1",
                "success": true,
                "run": run,
                "population": population,
                "risk_class": risk_name(risk),
                "additional_required_roles": additional_role_count,
                "governed_minimum_organizations": governed_minimum_organizations(risk),
                "logical_records_only": true,
                "cryptographic_provisioning_evaluated": false,
                "synthesis_ns": synthesis_ns,
                "policy": {
                    "clause_count": clause_count,
                    "evidence_count": evidence_count,
                    "clause_member_references": clause_member_references,
                    "maximum_clause_members": maximum_clause_members,
                    "exact_clause_count": exact_clause_count,
                    "canonical_bytes": encoded.len(),
                    "policy_hash": result.policy_hash.to_string(),
                },
                "evidence": result.evidence,
            }))
        }
        Err(error) => Ok(json!({
            "schema": "astra-pq-synthesis-scale-v1",
            "success": false,
            "run": run,
            "population": population,
            "risk_class": risk_name(risk),
            "additional_required_roles": additional_role_count,
            "governed_minimum_organizations": governed_minimum_organizations(risk),
            "logical_records_only": true,
            "cryptographic_provisioning_evaluated": false,
            "synthesis_ns": synthesis_ns,
            "error": error.to_string(),
        })),
    }
}

fn generated_registry(
    population: usize,
    additional_role_count: usize,
) -> anyhow::Result<(Vec<AuthorityRecord>, BTreeSet<String>)> {
    anyhow::ensure!(
        population >= 3,
        "population must contain at least three authorities"
    );

    let mut authorities = (1..=population)
        .map(|index| AuthorityRecord {
            id: format!("a{index:03}"),
            domain: match index {
                1 => "domain-a".to_owned(),
                2 => "domain-b".to_owned(),
                3 => "safety-domain".to_owned(),
                4 => "human-oversight-domain".to_owned(),
                _ => format!("domain-{index:03}"),
            },
            organization: format!("organization-{index:03}"),
            roles: special_roles(index),
            is_destination_authority: index == 2,
            eligible: true,
            online: true,
            revoked: false,
        })
        .collect::<Vec<_>>();

    let required_roles = (1..=additional_role_count)
        .map(|index| format!("additional-role-{index:02}"))
        .collect::<BTreeSet<_>>();
    for (index, role) in required_roles.iter().enumerate() {
        authorities[index % population].roles.insert(role.clone());
    }
    Ok((authorities, required_roles))
}

fn special_roles(index: usize) -> BTreeSet<String> {
    match index {
        1 => BTreeSet::from(["source".to_owned()]),
        3 => BTreeSet::from(["safety".to_owned()]),
        4 => BTreeSet::from(["human-confirmation".to_owned()]),
        _ => BTreeSet::new(),
    }
}

fn benchmark_context(
    population: usize,
    risk: RiskClass,
    additional_role_count: usize,
    run: usize,
) -> SessionContext {
    let mut session_id = [0_u8; 32];
    session_id[0..8].copy_from_slice(&(population as u64).to_be_bytes());
    session_id[8] = risk.wire_value();
    session_id[9..17].copy_from_slice(&(additional_role_count as u64).to_be_bytes());
    session_id[17..25].copy_from_slice(&(run as u64).to_be_bytes());
    session_id[25..32].fill(0xa5);

    SessionContext {
        protocol_version: PROTOCOL_VERSION,
        session_id: SessionId::from_bytes(session_id),
        epoch: EPOCH,
        source_domain: "domain-a".to_owned(),
        destination_domain: "domain-b".to_owned(),
        subject: "synthetic-operator:17".to_owned(),
        resource: "synthetic-plc:4".to_owned(),
        action: "synthetic-risk-adaptive-operation".to_owned(),
        risk,
        gateway_transcript_hash: Digest32::from_bytes([2; 32]),
        checkpoint_hash: Digest32::from_bytes([3; 32]),
    }
}

const fn governed_minimum_organizations(risk: RiskClass) -> Option<u16> {
    match risk {
        RiskClass::R4 => Some(4),
        RiskClass::R0 | RiskClass::R1 | RiskClass::R2 | RiskClass::R3 => None,
    }
}

const fn risk_name(risk: RiskClass) -> &'static str {
    match risk {
        RiskClass::R0 => "R0",
        RiskClass::R1 => "R1",
        RiskClass::R2 => "R2",
        RiskClass::R3 => "R3",
        RiskClass::R4 => "R4",
    }
}

fn environment_usize(name: &str, default: usize) -> anyhow::Result<usize> {
    match env::var(name) {
        Ok(value) => value
            .parse::<usize>()
            .with_context(|| format!("parse {name} as a nonnegative integer")),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(error).with_context(|| format!("read {name}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_registry_has_required_special_roles() {
        let (authorities, required_roles) = generated_registry(50, 8).unwrap();
        assert_eq!(authorities.len(), 50);
        assert_eq!(required_roles.len(), 8);
        assert!(authorities[0].roles.contains("source"));
        assert!(authorities[2].roles.contains("safety"));
        assert!(authorities[3].roles.contains("human-confirmation"));
        assert!(required_roles.iter().all(|role| {
            authorities
                .iter()
                .any(|authority| authority.roles.contains(role))
        }));
    }

    #[test]
    fn r4_requires_at_least_four_organizations() {
        let (three, roles) = generated_registry(3, 0).unwrap();
        let request = SynthesisRequest {
            context: benchmark_context(3, RiskClass::R4, 0, 1),
            authorities: three,
            required_roles: roles,
            minimum_organizations: governed_minimum_organizations(RiskClass::R4),
        };
        assert!(synthesize(&request).is_err());

        let (four, roles) = generated_registry(4, 0).unwrap();
        let request = SynthesisRequest {
            context: benchmark_context(4, RiskClass::R4, 0, 1),
            authorities: four,
            required_roles: roles,
            minimum_organizations: governed_minimum_organizations(RiskClass::R4),
        };
        assert!(synthesize(&request).is_ok());
    }
}
