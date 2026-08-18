//! Threshold-scaling benchmark for the ASTRA-PQ exact-coalition LWR backend.
//!
//! The benchmark emits one compact JSON object per sample. It measures local,
//! sequential computation only. It does not measure network transport or claim
//! malicious robustness.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use anyhow::Context;
use astra_common::Digest32;
use astra_dprf::{
    ClausePolicy, DprfBackend, EvaluationRequest,
    lwr::{LwrExactCoalitionBackend, setup_exact_coalition},
};
use serde_json::json;
use std::collections::BTreeMap;
use std::env;
use std::time::Instant;

const EPOCH: u64 = 1;
const SHARE_VERSION: u64 = 1;
const DEFAULT_MIN_THRESHOLD: usize = 1;
const DEFAULT_MAX_THRESHOLD: usize = 7;
const DEFAULT_REPETITIONS: usize = 100;

fn main() -> anyhow::Result<()> {
    let minimum = environment_usize("ASTRA_SCALE_MIN", DEFAULT_MIN_THRESHOLD)?;
    let maximum = environment_usize("ASTRA_SCALE_MAX", DEFAULT_MAX_THRESHOLD)?;
    let repetitions = environment_usize("ASTRA_SCALE_REPETITIONS", DEFAULT_REPETITIONS)?;
    anyhow::ensure!(minimum >= 1, "minimum threshold must be at least one");
    anyhow::ensure!(maximum >= minimum, "maximum threshold is below minimum");
    anyhow::ensure!(maximum <= 32, "maximum threshold exceeds backend limit");
    anyhow::ensure!(repetitions >= 1, "repetitions must be at least one");

    let backend = LwrExactCoalitionBackend;
    for threshold in minimum..=maximum {
        let authorities: Vec<String> = (1..=threshold)
            .map(|index| format!("authority-{index}"))
            .collect();
        let clause_id = format!("scale-t{threshold}");
        let policy = exact_policy(&clause_id, &authorities)?;

        for run in 1..=repetitions {
            let request = EvaluationRequest {
                clause_id: clause_id.clone(),
                epoch: EPOCH,
                share_version: SHARE_VERSION,
                input: sample_input(threshold, run),
            };
            let total_start = Instant::now();

            let setup_start = Instant::now();
            let shares = setup_exact_coalition(&clause_id, EPOCH, SHARE_VERSION, &authorities)
                .context("generate exact-coalition shares")?;
            let setup_us = elapsed_microseconds(setup_start);
            let secret_share_bytes_total: usize =
                shares.values().map(|share| share.secret_size_bytes()).sum();

            let partial_start = Instant::now();
            let partials = authorities
                .iter()
                .map(|authority| {
                    let share = shares
                        .get(authority)
                        .context("missing generated authority share")?;
                    backend
                        .partial_evaluate(authority, share, &request)
                        .map_err(anyhow::Error::from)
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            let partial_evaluation_us = elapsed_microseconds(partial_start);
            let partial_payload_bytes_total: usize =
                partials.iter().map(|partial| partial.payload.len()).sum();

            let combine_start = Instant::now();
            let output = backend
                .combine(&policy, &request, &partials)
                .context("combine exact-coalition partials")?;
            let combine_us = elapsed_microseconds(combine_start);
            anyhow::ensure!(
                output.expose_secret().iter().any(|byte| *byte != 0),
                "unexpected all-zero distributed output"
            );

            let report = json!({
                "schema": "astra-pq-lwr-scale-v1",
                "success": true,
                "run": run,
                "threshold": threshold,
                "eligible_authorities": threshold,
                "exact_coalition": true,
                "execution_model": "single-process-sequential",
                "security_profile": LwrExactCoalitionBackend::security_profile(),
                "malicious_robust": false,
                "proactive_refresh_implemented": false,
                "secret_share_bytes_total": secret_share_bytes_total,
                "partial_payload_bytes_total": partial_payload_bytes_total,
                "timing_us": {
                    "share_setup": setup_us,
                    "partial_evaluations_sequential": partial_evaluation_us,
                    "combine": combine_us,
                    "total": elapsed_microseconds(total_start)
                }
            });
            println!("{}", serde_json::to_string(&report)?);
        }
    }
    Ok(())
}

fn exact_policy(clause_id: &str, authorities: &[String]) -> anyhow::Result<ClausePolicy> {
    let threshold = u16::try_from(authorities.len())
        .context("authority count does not fit the policy threshold")?;
    Ok(ClausePolicy {
        clause_id: clause_id.to_owned(),
        threshold,
        members: authorities
            .iter()
            .enumerate()
            .map(|(index, authority)| (authority.clone(), format!("organization-{}", index + 1)))
            .collect::<BTreeMap<_, _>>(),
        require_distinct_organizations: true,
    })
}

fn sample_input(threshold: usize, run: usize) -> Digest32 {
    let mut bytes = [0_u8; 32];
    bytes[0..8].copy_from_slice(&(threshold as u64).to_be_bytes());
    bytes[8..16].copy_from_slice(&(run as u64).to_be_bytes());
    bytes[16..32].fill(0xa5);
    Digest32::from_bytes(bytes)
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

fn elapsed_microseconds(start: Instant) -> u128 {
    start.elapsed().as_micros()
}
