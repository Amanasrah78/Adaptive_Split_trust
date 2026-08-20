//! Gateway-side distributed authorization benchmark for the ASTRA-PQ VM lab.
//!
//! This client measures the authenticated distributed-authorization path. It
//! is distinct from the full in-process gateway/KEM experiment and uses a
//! bounded JSON-over-TCP lab transport without confidentiality.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use anyhow::Context;
use astra_authority::{
    AuthorityRequest, SignedPartialEvidence, sign_authority_request, verify_evidence,
};
use astra_common::{
    Digest32, PROTOCOL_VERSION, RiskClass, SessionContext, SessionId, authorization_input,
    hash_domain_separated,
};
use astra_dprf::{ClausePolicy, DprfBackend, EvaluationRequest, lwr::LwrExactCoalitionBackend};
use astra_governance::{
    GovernanceBundle, LocalGovernanceState, checkpoint_is_fresh, validate_bundle,
};
use astra_pqcrypto::PqProvider;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const WIRE_SCHEMA: &str = "astra-pq-authority-wire-v1";
const REPORT_SCHEMA: &str = "astra-pq-distributed-authorization-v1";
const MAX_FRAME_BYTES: usize = 1_048_576;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const SELECTION_CONNECT_TIMEOUT: Duration = Duration::from_millis(500);
const EPOCH: u64 = 1;
const SHARE_VERSION: u64 = 1;
const POLICY_LABEL: &[u8] = b"ASTRA-PQ-DISTRIBUTED-SCALE-POLICY-v1";
const SESSION_LABEL: &[u8] = b"ASTRA-PQ-DISTRIBUTED-SCALE-SESSION-v1";

#[derive(Debug, Serialize, Deserialize)]
struct AuthorityWireResponse {
    schema: String,
    authority_id: String,
    success: bool,
    evidence: Option<SignedPartialEvidence>,
    error: Option<String>,
    processing_us: u128,
}

struct NetworkEvidence {
    authority_id: String,
    evidence: SignedPartialEvidence,
    round_trip_us: u128,
    authority_processing_us: u128,
    response_bytes: usize,
}

struct AuthorityConnection {
    authority_id: String,
    stream: TcpStream,
}

fn main() -> anyhow::Result<()> {
    let threshold = required_usize("ASTRA_THRESHOLD")?;
    let repetitions = required_usize("ASTRA_REPETITIONS")?;
    anyhow::ensure!(
        (1..=7).contains(&threshold),
        "threshold is outside lab bounds"
    );
    anyhow::ensure!(repetitions >= 1, "repetitions must be positive");
    let gateway_id = required_environment("ASTRA_GATEWAY_ID")?;
    let governance_path = PathBuf::from(required_environment("ASTRA_GOVERNANCE_BUNDLE")?);
    let endpoints = parse_endpoints(&required_environment("ASTRA_AUTHORITY_ENDPOINTS")?)?;
    let excluded_authorities = optional_identifier_set("ASTRA_EXCLUDED_AUTHORITIES")?;
    for authority in &excluded_authorities {
        anyhow::ensure!(
            endpoints.contains_key(authority),
            "excluded authority {authority} is not configured"
        );
    }
    let gateway_secret_path = PathBuf::from(required_environment("ASTRA_GATEWAY_SIGNING_KEY")?);
    let gateway_public_path = PathBuf::from(required_environment("ASTRA_GATEWAY_PUBLIC_KEY")?);
    let authority_key_root =
        PathBuf::from(required_environment("ASTRA_AUTHORITY_PUBLIC_KEY_ROOT")?);
    let provider = PqProvider::new().context("initialize post-quantum provider")?;
    let governance_bundle: GovernanceBundle = serde_json::from_slice(
        &fs::read(&governance_path)
            .with_context(|| format!("read {}", governance_path.display()))?,
    )
    .context("decode governance bundle")?;
    let governance_state = validate_bundle(
        &provider,
        &LocalGovernanceState::default(),
        &governance_bundle,
        unix_time()?,
    )
    .context("validate off-path governance bundle")?;
    anyhow::ensure!(
        governance_bundle.checkpoint.epoch == EPOCH,
        "governance epoch differs from provisioned LWR epoch"
    );
    let checkpoint = governance_state.checkpoint_hash;
    let gateway_secret = provider.import_signature_secret_key(
        fs::read(&gateway_secret_path)
            .with_context(|| format!("read {}", gateway_secret_path.display()))?,
    )?;
    let gateway_public = fs::read(&gateway_public_path)
        .with_context(|| format!("read {}", gateway_public_path.display()))?;
    let self_test_message = b"ASTRA-PQ gateway request-key startup self-test v1";
    let self_test_signature = provider.sign(&gateway_secret, self_test_message)?;
    provider
        .verify(&gateway_public, self_test_message, &self_test_signature)
        .context("gateway request-signing key mismatch")?;

    let selection_start = Instant::now();
    let mut unreachable_authorities = Vec::new();
    let mut reachable_authorities = Vec::new();
    let mut connections = Vec::new();
    for (authority, endpoint) in &endpoints {
        if excluded_authorities.contains(authority) {
            continue;
        }
        match connect_authority(authority, *endpoint, SELECTION_CONNECT_TIMEOUT) {
            Ok(connection) => {
                reachable_authorities.push(authority.clone());
                connections.push(connection);
            }
            Err(_) => unreachable_authorities.push(authority.clone()),
        }
    }
    anyhow::ensure!(
        connections.len() >= threshold,
        "no policy-compliant coalition is reachable: threshold={threshold}, reachable={}",
        connections.len()
    );
    let authority_ids = select_coalition(&reachable_authorities, threshold)?;
    connections.truncate(threshold);
    let coalition_selection_us = selection_start.elapsed().as_micros();
    let authority_public_keys = authority_ids
        .iter()
        .map(|authority| {
            let path = authority_key_root.join(format!("{authority}.pk"));
            let key = fs::read(&path)
                .with_context(|| format!("read authority key {}", path.display()))?;
            Ok((authority.clone(), key))
        })
        .collect::<anyhow::Result<BTreeMap<_, _>>>()?;
    let policy = exact_policy(threshold, &authority_ids)?;
    let policy_hash = scale_policy_hash(&policy);
    let invocation_key = provider.generate_kem_keypair()?;
    let invocation_nonce = hash_domain_separated(
        b"ASTRA-PQ-DISTRIBUTED-INVOCATION-v1",
        &[invocation_key.public_key()],
    );
    let coordinated_start_barrier = wait_for_benchmark_start()?;
    let backend = LwrExactCoalitionBackend;
    for run in 1..=repetitions {
        anyhow::ensure!(
            checkpoint_is_fresh(
                &governance_state,
                &governance_bundle.checkpoint,
                unix_time()?
            ),
            "cached governance checkpoint is stale"
        );
        let total_start = Instant::now();
        let context = experiment_context(run, threshold, checkpoint, invocation_nonce);
        let input = authorization_input(&context, &policy_hash)?;
        let request = AuthorityRequest {
            context: context.clone(),
            policy_hash,
            evaluation: EvaluationRequest {
                clause_id: policy.clause_id.clone(),
                epoch: EPOCH,
                share_version: SHARE_VERSION,
                input,
            },
        };

        let signing_start = Instant::now();
        let signed = sign_authority_request(&provider, &gateway_id, &gateway_secret, request)?;
        let gateway_signing_us = signing_start.elapsed().as_micros();
        let encoded_request = serde_json::to_vec(&signed)?;

        let network_start = Instant::now();
        let network_results = thread::scope(|scope| {
            let handles = connections
                .iter_mut()
                .map(|connection| {
                    let encoded_request = &encoded_request;
                    scope.spawn(move || request_evidence(connection, encoded_request))
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .map_err(|_| anyhow::anyhow!("authority worker panicked"))?
                })
                .collect::<anyhow::Result<Vec<_>>>()
        })?;
        let parallel_collection_us = network_start.elapsed().as_micros();

        let verification_start = Instant::now();
        for result in &network_results {
            let public_key = authority_public_keys
                .get(&result.authority_id)
                .context("response came from an unconfigured authority")?;
            verify_evidence(&provider, public_key, &context, &result.evidence)
                .with_context(|| format!("verify evidence from {}", result.authority_id))?;
            anyhow::ensure!(
                result.evidence.policy_hash == policy_hash,
                "authority evidence uses a different policy hash"
            );
        }
        let evidence_verification_us = verification_start.elapsed().as_micros();
        let partials = network_results
            .iter()
            .map(|result| result.evidence.partial.clone())
            .collect::<Vec<_>>();

        let combine_start = Instant::now();
        let authorization_secret =
            backend.combine(&policy, &signed.request.evaluation, &partials)?;
        let combine_us = combine_start.elapsed().as_micros();
        anyhow::ensure!(
            authorization_secret
                .expose_secret()
                .iter()
                .any(|byte| *byte != 0),
            "distributed authorization output is all zero"
        );

        let round_trips: Vec<u128> = network_results
            .iter()
            .map(|result| result.round_trip_us)
            .collect();
        let authority_processing: Vec<u128> = network_results
            .iter()
            .map(|result| result.authority_processing_us)
            .collect();
        let total_response_bytes: usize = network_results
            .iter()
            .map(|result| result.response_bytes)
            .sum();
        let report = json!({
            "schema": REPORT_SCHEMA,
            "success": true,
            "run": run,
            "threshold": threshold,
            "configured_authorities": endpoints.len(),
            "policy_eligible_authorities": endpoints.keys().collect::<Vec<_>>(),
            "excluded_authorities": excluded_authorities,
            "unreachable_authorities": unreachable_authorities,
            "reachable_authorities": reachable_authorities,
            "selected_coalition": authority_ids,
            "coalition_clause_id": policy.clause_id,
            "coalition_selection_us": coalition_selection_us,
            "exact_coalition": true,
            "gateway_id": gateway_id,
            "authority_ids": authority_ids,
            "transport": "bounded-json-over-tcp-isolated-lab-no-confidentiality",
            "connection_mode": "persistent-preconnected-excluded-from-timing",
            "coordinated_start_barrier": coordinated_start_barrier,
            "governance_validation": "off-path-signed-bundle-synthetic-iota-observations",
            "live_iota_claim": false,
            "gateway_request_authentication": "ML-DSA-65",
            "authority_evidence_signature": "ML-DSA-65",
            "dprf_backend": backend.backend_id(),
            "security_profile": LwrExactCoalitionBackend::security_profile(),
            "malicious_robust": false,
            "proactive_refresh_implemented": false,
            "request_bytes_per_authority": encoded_request.len(),
            "response_bytes_total": total_response_bytes,
            "partial_payload_bytes_total": partials
                .iter()
                .map(|partial| partial.payload.len())
                .sum::<usize>(),
            "authority_round_trip_us": round_trips,
            "authority_processing_us": authority_processing,
            "timing_us": {
                "gateway_request_signing": gateway_signing_us,
                "parallel_authority_collection": parallel_collection_us,
                "evidence_verification_sequential": evidence_verification_us,
                "lwr_combine": combine_us,
                "distributed_authorization_total": total_start.elapsed().as_micros()
            }
        });
        println!("{}", serde_json::to_string(&report)?);
    }
    Ok(())
}

fn connect_authority(
    authority_id: &str,
    endpoint: SocketAddr,
    connect_timeout: Duration,
) -> anyhow::Result<AuthorityConnection> {
    let stream = TcpStream::connect_timeout(&endpoint, connect_timeout)
        .with_context(|| format!("connect to {authority_id} at {endpoint}"))?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    Ok(AuthorityConnection {
        authority_id: authority_id.to_owned(),
        stream,
    })
}

fn request_evidence(
    connection: &mut AuthorityConnection,
    encoded_request: &[u8],
) -> anyhow::Result<NetworkEvidence> {
    let start = Instant::now();
    write_frame(&mut connection.stream, encoded_request)?;
    let encoded_response = read_frame(&mut connection.stream)?;
    let round_trip_us = start.elapsed().as_micros();
    let response: AuthorityWireResponse = serde_json::from_slice(&encoded_response)
        .with_context(|| format!("decode response from {}", connection.authority_id))?;
    anyhow::ensure!(
        response.schema == WIRE_SCHEMA,
        "authority wire schema mismatch"
    );
    anyhow::ensure!(
        response.authority_id == connection.authority_id,
        "authority response identity mismatch"
    );
    anyhow::ensure!(
        response.success,
        "authority rejected request: {}",
        response
            .error
            .unwrap_or_else(|| "unspecified error".to_owned())
    );
    let evidence = response
        .evidence
        .context("successful response lacks evidence")?;
    Ok(NetworkEvidence {
        authority_id: connection.authority_id.clone(),
        evidence,
        round_trip_us,
        authority_processing_us: response.processing_us,
        response_bytes: encoded_response.len(),
    })
}

fn exact_policy(threshold: usize, authorities: &[String]) -> anyhow::Result<ClausePolicy> {
    anyhow::ensure!(
        authorities.len() == threshold,
        "selected coalition size differs from threshold"
    );
    Ok(ClausePolicy {
        clause_id: format!("distributed-t{threshold}-c-{}", authorities.join("-")),
        threshold: u16::try_from(threshold).context("threshold does not fit u16")?,
        members: authorities
            .iter()
            .enumerate()
            .map(|(index, authority)| (authority.clone(), format!("organization-{}", index + 1)))
            .collect(),
        require_distinct_organizations: true,
    })
}

fn select_coalition(
    reachable_authorities: &[String],
    threshold: usize,
) -> anyhow::Result<Vec<String>> {
    anyhow::ensure!(threshold > 0, "coalition threshold must be positive");
    anyhow::ensure!(
        reachable_authorities.len() >= threshold,
        "insufficient reachable authorities"
    );
    anyhow::ensure!(
        reachable_authorities
            .windows(2)
            .all(|pair| pair[0] < pair[1]),
        "reachable authority identifiers are duplicated or unsorted"
    );
    Ok(reachable_authorities[..threshold].to_vec())
}

fn scale_policy_hash(policy: &ClausePolicy) -> Digest32 {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&policy.threshold.to_be_bytes());
    encoded.extend_from_slice(policy.clause_id.as_bytes());
    for (authority, organization) in &policy.members {
        encoded.extend_from_slice(&(authority.len() as u64).to_be_bytes());
        encoded.extend_from_slice(authority.as_bytes());
        encoded.extend_from_slice(&(organization.len() as u64).to_be_bytes());
        encoded.extend_from_slice(organization.as_bytes());
    }
    hash_domain_separated(POLICY_LABEL, &[&encoded])
}

fn experiment_context(
    run: usize,
    threshold: usize,
    checkpoint: Digest32,
    invocation_nonce: Digest32,
) -> SessionContext {
    let run_bytes = (run as u64).to_be_bytes();
    let threshold_bytes = (threshold as u64).to_be_bytes();
    let session_digest = hash_domain_separated(
        SESSION_LABEL,
        &[invocation_nonce.as_bytes(), &run_bytes, &threshold_bytes],
    );
    SessionContext {
        protocol_version: PROTOCOL_VERSION,
        session_id: SessionId::from_bytes(*session_digest.as_bytes()),
        epoch: EPOCH,
        source_domain: "domain-a".to_owned(),
        destination_domain: "domain-b".to_owned(),
        subject: "synthetic-operator:17".to_owned(),
        resource: "synthetic-plc:4".to_owned(),
        action: "synthetic-safety-actuation".to_owned(),
        risk: if threshold == 1 {
            RiskClass::R0
        } else if threshold == 2 {
            RiskClass::R2
        } else {
            RiskClass::R4
        },
        gateway_transcript_hash: invocation_nonce,
        checkpoint_hash: checkpoint,
    }
}

fn parse_endpoints(encoded: &str) -> anyhow::Result<BTreeMap<String, SocketAddr>> {
    let mut endpoints = BTreeMap::new();
    for entry in encoded.split(',') {
        let (authority, endpoint) = entry
            .split_once('=')
            .context("authority endpoint must use id=address:port")?;
        anyhow::ensure!(
            !authority.is_empty()
                && authority.len() <= 256
                && !authority.chars().any(char::is_control),
            "invalid authority endpoint identifier"
        );
        let endpoint = endpoint
            .parse::<SocketAddr>()
            .with_context(|| format!("parse endpoint for {authority}"))?;
        anyhow::ensure!(
            endpoints.insert(authority.to_owned(), endpoint).is_none(),
            "duplicate endpoint for {authority}"
        );
    }
    anyhow::ensure!(!endpoints.is_empty(), "authority endpoint set is empty");
    Ok(endpoints)
}

fn optional_identifier_set(name: &str) -> anyhow::Result<BTreeSet<String>> {
    let Some(encoded) = env::var(name).ok() else {
        return Ok(BTreeSet::new());
    };
    if encoded.trim().is_empty() {
        return Ok(BTreeSet::new());
    }
    let mut identifiers = BTreeSet::new();
    for identifier in encoded.split(',') {
        anyhow::ensure!(
            !identifier.is_empty()
                && identifier.len() <= 256
                && !identifier.chars().any(char::is_control),
            "invalid identifier in {name}"
        );
        anyhow::ensure!(
            identifiers.insert(identifier.to_owned()),
            "duplicate identifier in {name}"
        );
    }
    Ok(identifiers)
}

fn read_frame(stream: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
    let mut length_bytes = [0_u8; 4];
    stream.read_exact(&mut length_bytes)?;
    let length = usize::try_from(u32::from_be_bytes(length_bytes))
        .context("frame length does not fit this platform")?;
    anyhow::ensure!(
        (1..=MAX_FRAME_BYTES).contains(&length),
        "invalid authority response length"
    );
    let mut encoded = vec![0_u8; length];
    stream.read_exact(&mut encoded)?;
    Ok(encoded)
}

fn write_frame(stream: &mut TcpStream, encoded: &[u8]) -> anyhow::Result<()> {
    anyhow::ensure!(
        (1..=MAX_FRAME_BYTES).contains(&encoded.len()),
        "invalid authority request length"
    );
    let length = u32::try_from(encoded.len()).context("request frame is too large")?;
    let mut frame = Vec::with_capacity(4 + encoded.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(encoded);
    stream.write_all(&frame)?;
    stream.flush()?;
    Ok(())
}

fn required_usize(name: &str) -> anyhow::Result<usize> {
    required_environment(name)?
        .parse::<usize>()
        .with_context(|| format!("parse {name} as a positive integer"))
}

fn required_environment(name: &str) -> anyhow::Result<String> {
    let value = env::var(name).with_context(|| format!("missing {name}"))?;
    anyhow::ensure!(!value.trim().is_empty(), "{name} is empty");
    Ok(value)
}

fn wait_for_benchmark_start() -> anyhow::Result<bool> {
    let ready_file = env::var("ASTRA_BENCHMARK_READY_FILE").ok();
    let start_file = env::var("ASTRA_BENCHMARK_START_FILE").ok();
    let (ready_file, start_file) = match (ready_file, start_file) {
        (None, None) => return Ok(false),
        (Some(ready_file), Some(start_file)) => {
            (PathBuf::from(ready_file), PathBuf::from(start_file))
        }
        _ => anyhow::bail!(
            "ASTRA_BENCHMARK_READY_FILE and ASTRA_BENCHMARK_START_FILE must be set together"
        ),
    };
    let timeout_seconds = env::var("ASTRA_BENCHMARK_BARRIER_TIMEOUT_SECONDS")
        .unwrap_or_else(|_| "30".to_owned())
        .parse::<u64>()
        .context("parse ASTRA_BENCHMARK_BARRIER_TIMEOUT_SECONDS")?;
    anyhow::ensure!(
        timeout_seconds > 0,
        "benchmark barrier timeout must be positive"
    );
    anyhow::ensure!(
        !start_file.exists(),
        "benchmark start file already exists before readiness"
    );
    fs::write(&ready_file, b"ready\n")
        .with_context(|| format!("write benchmark ready file {}", ready_file.display()))?;
    let deadline = Instant::now() + Duration::from_secs(timeout_seconds);
    while !start_file.exists() {
        anyhow::ensure!(
            Instant::now() < deadline,
            "timed out waiting for benchmark start file {}",
            start_file.display()
        );
        thread::sleep(Duration::from_millis(2));
    }
    Ok(true)
}

fn unix_time() -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock precedes Unix epoch")?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reachable_coalition_selection_is_deterministic() {
        let reachable = vec![
            "a2".to_owned(),
            "a3".to_owned(),
            "a5".to_owned(),
            "a7".to_owned(),
        ];
        assert_eq!(
            select_coalition(&reachable, 3).unwrap(),
            vec!["a2".to_owned(), "a3".to_owned(), "a5".to_owned()]
        );
        assert!(select_coalition(&reachable, 5).is_err());
    }

    #[test]
    fn exact_policy_binds_selected_coalition() {
        let authorities = vec!["a1".to_owned(), "a4".to_owned(), "a7".to_owned()];
        let policy = exact_policy(3, &authorities).unwrap();
        assert_eq!(policy.clause_id, "distributed-t3-c-a1-a4-a7");
        assert_eq!(policy.threshold, 3);
        assert_eq!(policy.members.len(), 3);
    }

    #[test]
    fn duplicate_endpoint_identifier_is_rejected() {
        assert!(parse_endpoints("a1=127.0.0.1:1,a1=127.0.0.1:2").is_err());
    }
}
