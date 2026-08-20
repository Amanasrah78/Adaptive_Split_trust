//! Isolated primitive benchmark for the ASTRA-PQ evaluation.
//!
//! The executable emits one JSON object per sample. It measures local,
//! sequential operations and does not include network transport.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use anyhow::Context;
use astra_common::{Digest32, Secret32, hash_domain_separated};
use astra_dprf::{
    ClausePolicy, DprfBackend, EvaluationRequest,
    lwr::{LwrExactCoalitionBackend, setup_exact_coalition},
};
use astra_pqcrypto::{
    ConfirmationRole, PqProvider, derive_session_confirmation_tag, derive_session_key,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::env;
use std::hint::black_box;
use std::time::Instant;

const EPOCH: u64 = 1;
const SHARE_VERSION: u64 = 1;
const DEFAULT_REPETITIONS: usize = 1_000;
const DEFAULT_WARMUP_ITERATIONS: usize = 100;
const DEFAULT_MESSAGE_BYTES: usize = 1_024;
const LWR_THRESHOLD: usize = 3;
const HASH_LABEL: &[u8] = b"ASTRA-PQ-PRIMITIVE-BENCH-HASH-v1";

fn main() -> anyhow::Result<()> {
    let repetitions = environment_usize("ASTRA_PRIMITIVE_REPETITIONS", DEFAULT_REPETITIONS)?;
    let warmup_iterations = environment_usize(
        "ASTRA_PRIMITIVE_WARMUP_ITERATIONS",
        DEFAULT_WARMUP_ITERATIONS,
    )?;
    let message_bytes = environment_usize("ASTRA_PRIMITIVE_MESSAGE_BYTES", DEFAULT_MESSAGE_BYTES)?;
    anyhow::ensure!(repetitions >= 1, "repetitions must be at least one");
    anyhow::ensure!(message_bytes >= 1, "message length must be at least one");
    anyhow::ensure!(message_bytes <= 1_048_576, "message exceeds protocol bound");

    let provider_start = Instant::now();
    let provider = PqProvider::new().context("initialize post-quantum provider")?;
    let provider_initialization_ns = elapsed_nanoseconds(provider_start);
    let metadata = provider.metadata();
    let message = vec![0xa5_u8; message_bytes];
    let serialization_value = json!({
        "schema": "astra-pq-primitive-serialization-v1",
        "message": "a".repeat(message_bytes),
        "epoch": EPOCH,
        "share_version": SHARE_VERSION,
    });
    let authorities = (1..=LWR_THRESHOLD)
        .map(|index| format!("a{index}"))
        .collect::<Vec<_>>();
    let clause_id = "primitive-bench-t3";
    let policy = exact_policy(clause_id, &authorities)?;

    for warmup in 0..warmup_iterations {
        black_box(measure_sample(
            &provider,
            &message,
            &serialization_value,
            clause_id,
            &authorities,
            &policy,
            warmup + 1,
        )?);
    }

    for run in 1..=repetitions {
        let mut report = measure_sample(
            &provider,
            &message,
            &serialization_value,
            clause_id,
            &authorities,
            &policy,
            run,
        )?;
        report["run"] = json!(run);
        report["repetitions"] = json!(repetitions);
        report["warmup_iterations"] = json!(warmup_iterations);
        report["provider_initialization_ns"] = json!(provider_initialization_ns);
        report["provider"] = json!({
            "kem_algorithm": metadata.kem_algorithm,
            "kem_implementation": metadata.kem_implementation,
            "kem_nist_level": metadata.kem_nist_level,
            "signature_algorithm": metadata.signature_algorithm,
            "signature_implementation": metadata.signature_implementation,
            "signature_nist_level": metadata.signature_nist_level,
        });
        println!("{}", serde_json::to_string(&report)?);
    }
    Ok(())
}

fn measure_sample(
    provider: &PqProvider,
    message: &[u8],
    serialization_value: &Value,
    clause_id: &str,
    authorities: &[String],
    policy: &ClausePolicy,
    sample_number: usize,
) -> anyhow::Result<Value> {
    let start = Instant::now();
    let kem_keypair = provider
        .generate_kem_keypair()
        .context("generate ML-KEM key pair")?;
    let kem_key_generation_ns = elapsed_nanoseconds(start);

    let start = Instant::now();
    let encapsulation = provider
        .encapsulate(black_box(kem_keypair.public_key()))
        .context("encapsulate ML-KEM shared secret")?;
    let kem_encapsulation_ns = elapsed_nanoseconds(start);

    let start = Instant::now();
    let decapsulated = provider
        .decapsulate(
            kem_keypair.secret_key(),
            black_box(encapsulation.ciphertext()),
        )
        .context("decapsulate ML-KEM shared secret")?;
    let kem_decapsulation_ns = elapsed_nanoseconds(start);
    anyhow::ensure!(
        decapsulated.expose_secret() == encapsulation.shared_secret().expose_secret(),
        "ML-KEM shared secrets differ"
    );

    let start = Instant::now();
    let signature_keypair = provider
        .generate_signature_keypair()
        .context("generate ML-DSA key pair")?;
    let signature_key_generation_ns = elapsed_nanoseconds(start);

    let start = Instant::now();
    let signature = provider
        .sign(signature_keypair.secret_key(), black_box(message))
        .context("sign ML-DSA message")?;
    let signature_sign_ns = elapsed_nanoseconds(start);

    let start = Instant::now();
    provider
        .verify(
            signature_keypair.public_key(),
            black_box(message),
            black_box(&signature),
        )
        .context("verify ML-DSA signature")?;
    let signature_verify_ns = elapsed_nanoseconds(start);

    let start = Instant::now();
    let digest = hash_domain_separated(HASH_LABEL, &[black_box(message)]);
    black_box(digest);
    let sha3_256_domain_hash_ns = elapsed_nanoseconds(start);

    let authorization_secret = Secret32::from_bytes([0x5a; 32]);
    let authorization_input = sample_input(sample_number);
    let start = Instant::now();
    let session_key = derive_session_key(
        encapsulation.shared_secret(),
        &authorization_secret,
        &authorization_input,
        black_box(message),
    )
    .context("derive dual-gate session key")?;
    let session_key_derivation_ns = elapsed_nanoseconds(start);

    let start = Instant::now();
    let confirmation = derive_session_confirmation_tag(
        &session_key,
        black_box(message),
        ConfirmationRole::Initiator,
    )
    .context("derive session confirmation tag")?;
    black_box(confirmation);
    let confirmation_tag_derivation_ns = elapsed_nanoseconds(start);

    let start = Instant::now();
    let serialized = serde_json::to_vec(black_box(serialization_value))
        .context("serialize representative JSON value")?;
    let json_serialization_ns = elapsed_nanoseconds(start);

    let start = Instant::now();
    let decoded: Value = serde_json::from_slice(black_box(&serialized))
        .context("deserialize representative JSON value")?;
    black_box(decoded);
    let json_deserialization_ns = elapsed_nanoseconds(start);

    let request = EvaluationRequest {
        clause_id: clause_id.to_owned(),
        epoch: EPOCH,
        share_version: SHARE_VERSION,
        input: authorization_input,
    };
    let backend = LwrExactCoalitionBackend;

    let start = Instant::now();
    let shares = setup_exact_coalition(clause_id, EPOCH, SHARE_VERSION, authorities)
        .context("generate exact-coalition LWR shares")?;
    let lwr_share_setup_ns = elapsed_nanoseconds(start);
    let secret_share_bytes_total = shares
        .values()
        .map(|share| share.secret_size_bytes())
        .sum::<usize>();

    let start = Instant::now();
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
    let lwr_partial_evaluations_ns = elapsed_nanoseconds(start);
    let partial_payload_bytes_total = partials
        .iter()
        .map(|partial| partial.payload.len())
        .sum::<usize>();

    let start = Instant::now();
    let output = backend
        .combine(policy, &request, &partials)
        .context("combine exact-coalition LWR partials")?;
    let lwr_combine_ns = elapsed_nanoseconds(start);
    anyhow::ensure!(
        output.expose_secret().iter().any(|byte| *byte != 0),
        "unexpected all-zero LWR output"
    );

    Ok(json!({
        "schema": "astra-pq-primitive-benchmark-v1",
        "success": true,
        "execution_model": "single-process-sequential-interleaved",
        "message_bytes": message.len(),
        "lwr_threshold": LWR_THRESHOLD,
        "security_profile": LwrExactCoalitionBackend::security_profile(),
        "malicious_robust": false,
        "proactive_refresh_implemented": false,
        "sizes": {
            "kem_public_key_bytes": kem_keypair.public_key().len(),
            "kem_secret_key_bytes": kem_keypair.secret_key().len(),
            "kem_ciphertext_bytes": encapsulation.ciphertext().len(),
            "kem_shared_secret_bytes": encapsulation.shared_secret().len(),
            "signature_public_key_bytes": signature_keypair.public_key().len(),
            "signature_secret_key_bytes": signature_keypair.secret_key().len(),
            "signature_bytes": signature.len(),
            "representative_json_bytes": serialized.len(),
            "lwr_secret_share_bytes_total": secret_share_bytes_total,
            "lwr_partial_payload_bytes_total": partial_payload_bytes_total,
        },
        "timing_ns": {
            "kem_key_generation": kem_key_generation_ns,
            "kem_encapsulation": kem_encapsulation_ns,
            "kem_decapsulation": kem_decapsulation_ns,
            "signature_key_generation": signature_key_generation_ns,
            "signature_sign": signature_sign_ns,
            "signature_verify": signature_verify_ns,
            "sha3_256_domain_hash": sha3_256_domain_hash_ns,
            "session_key_derivation": session_key_derivation_ns,
            "confirmation_tag_derivation": confirmation_tag_derivation_ns,
            "json_serialization": json_serialization_ns,
            "json_deserialization": json_deserialization_ns,
            "lwr_share_setup": lwr_share_setup_ns,
            "lwr_partial_evaluations_sequential": lwr_partial_evaluations_ns,
            "lwr_combine": lwr_combine_ns,
        }
    }))
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

fn sample_input(sample_number: usize) -> Digest32 {
    let mut bytes = [0xa5_u8; 32];
    bytes[0..8].copy_from_slice(&(sample_number as u64).to_be_bytes());
    Digest32::from_bytes(bytes)
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

fn elapsed_nanoseconds(start: Instant) -> u128 {
    start.elapsed().as_nanos()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_inputs_change_by_sample_number() {
        assert_ne!(sample_input(1), sample_input(2));
    }

    #[test]
    fn exact_policy_requires_every_member() {
        let authorities = vec!["a1".to_owned(), "a2".to_owned(), "a3".to_owned()];
        let policy = exact_policy("test", &authorities).unwrap();
        assert_eq!(policy.threshold, 3);
        assert_eq!(policy.members.len(), 3);
        assert!(policy.require_distinct_organizations);
    }
}
