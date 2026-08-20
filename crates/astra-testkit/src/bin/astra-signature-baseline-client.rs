//! Persistent-channel client for centralized and static ML-DSA baselines.
//!
//! These comparison profiles produce signed authorization decisions, not an
//! ASTRA-PQ distributed pseudorandom authorization secret. They therefore
//! quantify performance overhead but are not security-equivalent substitutes.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use anyhow::Context;
use astra_common::{Digest32, PROTOCOL_VERSION, hash_domain_separated};
use astra_governance::{
    GovernanceBundle, LocalGovernanceState, checkpoint_is_fresh, validate_bundle,
};
use astra_pqcrypto::PqProvider;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const WIRE_SCHEMA: &str = "astra-pq-signature-baseline-wire-v1";
const REPORT_SCHEMA: &str = "astra-pq-signature-authorization-baseline-v1";
const REQUEST_LABEL: &[u8] = b"ASTRA-PQ-SIGNATURE-BASELINE-REQUEST-v1";
const REQUEST_HASH_LABEL: &[u8] = b"ASTRA-PQ-SIGNATURE-BASELINE-REQUEST-HASH-v1";
const APPROVAL_LABEL: &[u8] = b"ASTRA-PQ-SIGNATURE-BASELINE-APPROVAL-v1";
const INVOCATION_LABEL: &[u8] = b"ASTRA-PQ-SIGNATURE-BASELINE-INVOCATION-v1";
const MAX_FRAME_BYTES: usize = 1_048_576;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_millis(500);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BaselineProfile {
    Centralized,
    StaticQuorum,
}

impl BaselineProfile {
    fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "centralized" => Ok(Self::Centralized),
            "static-quorum" => Ok(Self::StaticQuorum),
            _ => anyhow::bail!("ASTRA_BASELINE_PROFILE must be centralized or static-quorum"),
        }
    }

    const fn wire_name(self) -> &'static str {
        match self {
            Self::Centralized => "centralized",
            Self::StaticQuorum => "static-quorum",
        }
    }

    const fn authority_ids(self) -> &'static [&'static str] {
        match self {
            Self::Centralized => &["a2"],
            Self::StaticQuorum => &["a1", "a2", "a3"],
        }
    }

    const fn trust_model(self) -> &'static str {
        match self {
            Self::Centralized => "single destination-authority trust",
            Self::StaticQuorum => "fixed three-authority signature quorum",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct BaselineAuthorizationRequest {
    protocol_version: u16,
    profile: String,
    run: u64,
    invocation_nonce: Digest32,
    epoch: u64,
    checkpoint_hash: Digest32,
    source_domain: String,
    destination_domain: String,
    subject: String,
    resource: String,
    action: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SignedBaselineRequest {
    gateway_id: String,
    request: BaselineAuthorizationRequest,
    signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SignedBaselineApproval {
    authority_id: String,
    gateway_id: String,
    profile: String,
    request_hash: Digest32,
    signature: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct BaselineWireResponse {
    schema: String,
    authority_id: String,
    success: bool,
    approval: Option<SignedBaselineApproval>,
    error: Option<String>,
    processing_us: u128,
}

struct AuthorityConnection {
    authority_id: String,
    stream: TcpStream,
}

struct NetworkApproval {
    authority_id: String,
    approval: SignedBaselineApproval,
    round_trip_us: u128,
    authority_processing_us: u128,
    response_bytes: usize,
}

fn main() -> anyhow::Result<()> {
    let profile = BaselineProfile::parse(&required_environment("ASTRA_BASELINE_PROFILE")?)?;
    let repetitions = required_usize("ASTRA_REPETITIONS")?;
    anyhow::ensure!(repetitions >= 1, "ASTRA_REPETITIONS must be positive");
    let gateway_id = required_environment("ASTRA_GATEWAY_ID")?;
    validate_identifier(&gateway_id, "gateway identifier")?;
    let governance_path = PathBuf::from(required_environment("ASTRA_GOVERNANCE_BUNDLE")?);
    let gateway_secret_path = PathBuf::from(required_environment("ASTRA_GATEWAY_SIGNING_KEY")?);
    let gateway_public_path = PathBuf::from(required_environment("ASTRA_GATEWAY_PUBLIC_KEY")?);
    let authority_key_root =
        PathBuf::from(required_environment("ASTRA_AUTHORITY_PUBLIC_KEY_ROOT")?);
    let endpoints = parse_endpoints(&required_environment("ASTRA_BASELINE_ENDPOINTS")?)?;

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
    let epoch = governance_bundle.checkpoint.epoch;
    let checkpoint_hash = governance_state.checkpoint_hash;

    let gateway_secret = provider.import_signature_secret_key(
        fs::read(&gateway_secret_path)
            .with_context(|| format!("read {}", gateway_secret_path.display()))?,
    )?;
    let gateway_public = fs::read(&gateway_public_path)
        .with_context(|| format!("read {}", gateway_public_path.display()))?;
    let self_test_message = b"ASTRA-PQ signature-baseline gateway-key startup self-test v1";
    let self_test_signature = provider.sign(&gateway_secret, self_test_message)?;
    provider
        .verify(&gateway_public, self_test_message, &self_test_signature)
        .context("gateway request-signing key mismatch")?;

    let authority_ids = profile.authority_ids();
    let authority_public_keys = authority_ids
        .iter()
        .map(|authority_id| {
            let path = authority_key_root.join(format!("{authority_id}.pk"));
            let key = fs::read(&path)
                .with_context(|| format!("read authority key {}", path.display()))?;
            Ok(((*authority_id).to_owned(), key))
        })
        .collect::<anyhow::Result<BTreeMap<_, _>>>()?;

    let connection_start = Instant::now();
    let mut connections = authority_ids
        .iter()
        .map(|authority_id| {
            let endpoint = endpoints.get(*authority_id).with_context(|| {
                format!("missing endpoint for required authority {authority_id}")
            })?;
            connect_authority(authority_id, *endpoint)
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let preconnection_us = connection_start.elapsed().as_micros();

    let invocation_key = provider.generate_kem_keypair()?;
    let invocation_nonce = hash_domain_separated(INVOCATION_LABEL, &[invocation_key.public_key()]);

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
        let request = BaselineAuthorizationRequest {
            protocol_version: PROTOCOL_VERSION,
            profile: profile.wire_name().to_owned(),
            run: u64::try_from(run).context("run does not fit u64")?,
            invocation_nonce,
            epoch,
            checkpoint_hash,
            source_domain: "domain-a".to_owned(),
            destination_domain: "domain-b".to_owned(),
            subject: "synthetic-operator".to_owned(),
            resource: "synthetic-plc:4".to_owned(),
            action: "synthetic-safety-actuation".to_owned(),
        };

        let signing_start = Instant::now();
        let message = request_message(&gateway_id, &request)?;
        let signed = SignedBaselineRequest {
            gateway_id: gateway_id.clone(),
            request,
            signature: provider.sign(&gateway_secret, &message)?,
        };
        let gateway_signing_us = signing_start.elapsed().as_micros();
        let encoded_request = serde_json::to_vec(&signed)?;
        let expected_request_hash = hash_domain_separated(REQUEST_HASH_LABEL, &[&message]);

        let collection_start = Instant::now();
        let network_results = thread::scope(|scope| {
            let handles = connections
                .iter_mut()
                .map(|connection| {
                    let encoded_request = &encoded_request;
                    scope.spawn(move || request_approval(connection, encoded_request))
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .map_err(|_| anyhow::anyhow!("baseline authority worker panicked"))?
                })
                .collect::<anyhow::Result<Vec<_>>>()
        })?;
        let parallel_collection_us = collection_start.elapsed().as_micros();

        let verification_start = Instant::now();
        for result in &network_results {
            let approval = &result.approval;
            anyhow::ensure!(
                approval.authority_id == result.authority_id,
                "approval authority identity mismatch"
            );
            anyhow::ensure!(
                approval.gateway_id == gateway_id,
                "approval gateway mismatch"
            );
            anyhow::ensure!(
                approval.profile == profile.wire_name(),
                "approval profile mismatch"
            );
            anyhow::ensure!(
                approval.request_hash == expected_request_hash,
                "approval request commitment mismatch"
            );
            let public_key = authority_public_keys
                .get(&result.authority_id)
                .context("approval came from an unconfigured authority")?;
            provider
                .verify(
                    public_key,
                    &approval_message(approval)?,
                    &approval.signature,
                )
                .with_context(|| format!("verify approval from {}", result.authority_id))?;
        }
        let approval_verification_us = verification_start.elapsed().as_micros();
        anyhow::ensure!(
            network_results.len() == authority_ids.len(),
            "baseline authorization lacks a required approval"
        );

        let round_trips = network_results
            .iter()
            .map(|result| result.round_trip_us)
            .collect::<Vec<_>>();
        let authority_processing = network_results
            .iter()
            .map(|result| result.authority_processing_us)
            .collect::<Vec<_>>();
        let response_bytes_total = network_results
            .iter()
            .map(|result| result.response_bytes)
            .sum::<usize>();
        let report = json!({
            "schema": REPORT_SCHEMA,
            "success": true,
            "run": run,
            "baseline_profile": profile.wire_name(),
            "trust_model": profile.trust_model(),
            "required_approvals": authority_ids.len(),
            "authority_ids": authority_ids,
            "authorization_decision": true,
            "distributed_authorization_secret": false,
            "security_equivalent_to_astra_pq": false,
            "comparison_purpose": "performance reference",
            "gateway_id": gateway_id,
            "governance_validation": "off-path-signed-bundle-synthetic-iota-observations",
            "live_iota_claim": false,
            "gateway_request_authentication": "ML-DSA-65",
            "authority_approval_signature": "ML-DSA-65",
            "lwr_evaluation": false,
            "transport": "bounded-json-over-tcp-isolated-lab-no-confidentiality",
            "connection_mode": "persistent-preconnected-excluded-from-timing",
            "preconnection_us_excluded": preconnection_us,
            "request_bytes_per_authority": encoded_request.len(),
            "response_bytes_total": response_bytes_total,
            "authority_round_trip_us": round_trips,
            "authority_processing_us": authority_processing,
            "timing_us": {
                "gateway_request_signing": gateway_signing_us,
                "parallel_authority_collection": parallel_collection_us,
                "approval_verification_sequential": approval_verification_us,
                "authorization_total": total_start.elapsed().as_micros()
            }
        });
        println!("{}", serde_json::to_string(&report)?);
    }
    Ok(())
}

fn connect_authority(
    authority_id: &str,
    endpoint: SocketAddr,
) -> anyhow::Result<AuthorityConnection> {
    let stream = TcpStream::connect_timeout(&endpoint, CONNECT_TIMEOUT)
        .with_context(|| format!("connect to baseline authority {authority_id} at {endpoint}"))?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    Ok(AuthorityConnection {
        authority_id: authority_id.to_owned(),
        stream,
    })
}

fn request_approval(
    connection: &mut AuthorityConnection,
    encoded_request: &[u8],
) -> anyhow::Result<NetworkApproval> {
    let start = Instant::now();
    write_frame(&mut connection.stream, encoded_request)?;
    let encoded_response = read_frame(&mut connection.stream)?;
    let round_trip_us = start.elapsed().as_micros();
    let response: BaselineWireResponse = serde_json::from_slice(&encoded_response)
        .with_context(|| format!("decode response from {}", connection.authority_id))?;
    anyhow::ensure!(
        response.schema == WIRE_SCHEMA,
        "baseline wire schema mismatch"
    );
    anyhow::ensure!(
        response.authority_id == connection.authority_id,
        "baseline authority response identity mismatch"
    );
    anyhow::ensure!(
        response.success,
        "baseline authority rejected request: {}",
        response.error.as_deref().unwrap_or("unspecified error")
    );
    let approval = response
        .approval
        .context("successful baseline response omitted approval")?;
    Ok(NetworkApproval {
        authority_id: connection.authority_id.clone(),
        approval,
        round_trip_us,
        authority_processing_us: response.processing_us,
        response_bytes: encoded_response.len(),
    })
}

fn request_message(
    gateway_id: &str,
    request: &BaselineAuthorizationRequest,
) -> anyhow::Result<Vec<u8>> {
    let encoded = serde_json::to_vec(&(gateway_id, request))?;
    Ok(domain_separated_message(REQUEST_LABEL, &encoded))
}

fn approval_message(approval: &SignedBaselineApproval) -> anyhow::Result<Vec<u8>> {
    let encoded = serde_json::to_vec(&(
        &approval.authority_id,
        &approval.gateway_id,
        &approval.profile,
        approval.request_hash,
    ))?;
    Ok(domain_separated_message(APPROVAL_LABEL, &encoded))
}

fn domain_separated_message(label: &[u8], encoded: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(label.len() + 8 + encoded.len());
    message.extend_from_slice(label);
    message.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
    message.extend_from_slice(encoded);
    message
}

fn parse_endpoints(encoded: &str) -> anyhow::Result<BTreeMap<String, SocketAddr>> {
    let mut endpoints = BTreeMap::new();
    for item in encoded.split(',') {
        let (authority_id, address) = item
            .split_once('=')
            .context("baseline endpoint must use authority=address")?;
        validate_identifier(authority_id, "authority identifier")?;
        let endpoint = address
            .parse::<SocketAddr>()
            .with_context(|| format!("parse endpoint for {authority_id}"))?;
        anyhow::ensure!(
            endpoints
                .insert(authority_id.to_owned(), endpoint)
                .is_none(),
            "duplicate baseline endpoint for {authority_id}"
        );
    }
    anyhow::ensure!(!endpoints.is_empty(), "baseline endpoint set is empty");
    Ok(endpoints)
}

fn read_frame(stream: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
    let mut length_bytes = [0_u8; 4];
    stream.read_exact(&mut length_bytes)?;
    let length = usize::try_from(u32::from_be_bytes(length_bytes))
        .context("frame length does not fit this platform")?;
    anyhow::ensure!(
        (1..=MAX_FRAME_BYTES).contains(&length),
        "invalid baseline response length"
    );
    let mut encoded = vec![0_u8; length];
    stream.read_exact(&mut encoded)?;
    Ok(encoded)
}

fn write_frame(stream: &mut TcpStream, encoded: &[u8]) -> anyhow::Result<()> {
    anyhow::ensure!(
        (1..=MAX_FRAME_BYTES).contains(&encoded.len()),
        "invalid baseline request length"
    );
    let length = u32::try_from(encoded.len()).context("baseline request frame is too large")?;
    let mut frame = Vec::with_capacity(4 + encoded.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(encoded);
    stream.write_all(&frame)?;
    stream.flush()?;
    Ok(())
}

fn validate_identifier(value: &str, description: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control),
        "invalid {description}"
    );
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
    fn profiles_select_the_intended_authorities() {
        let centralized = BaselineProfile::parse("centralized").unwrap();
        let quorum = BaselineProfile::parse("static-quorum").unwrap();
        assert_eq!(centralized.authority_ids(), &["a2"]);
        assert_eq!(quorum.authority_ids(), &["a1", "a2", "a3"]);
    }

    #[test]
    fn invalid_profile_is_rejected() {
        assert!(BaselineProfile::parse("dynamic").is_err());
    }

    #[test]
    fn duplicate_endpoint_identifier_is_rejected() {
        assert!(parse_endpoints("a1=127.0.0.1:7663,a1=127.0.0.1:7664").is_err());
    }
}
