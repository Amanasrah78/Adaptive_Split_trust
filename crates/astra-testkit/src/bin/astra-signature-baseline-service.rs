//! ML-DSA authorization-approval service used by the comparison baselines.
//!
//! The service deliberately excludes LWR evaluation. It validates the same
//! cached governance bundle and gateway-authenticated request used by the
//! ASTRA-PQ lab, then returns one authority-signed approval. The transport is
//! bounded JSON over TCP on the isolated experiment network and provides no
//! confidentiality.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use anyhow::Context;
use astra_common::{Digest32, PROTOCOL_VERSION, hash_domain_separated};
use astra_governance::{
    GovernanceBundle, LocalGovernanceState, checkpoint_is_fresh, validate_bundle,
};
use astra_pqcrypto::{PqProvider, SecretBytes};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const WIRE_SCHEMA: &str = "astra-pq-signature-baseline-wire-v1";
const REQUEST_LABEL: &[u8] = b"ASTRA-PQ-SIGNATURE-BASELINE-REQUEST-v1";
const REQUEST_HASH_LABEL: &[u8] = b"ASTRA-PQ-SIGNATURE-BASELINE-REQUEST-HASH-v1";
const APPROVAL_LABEL: &[u8] = b"ASTRA-PQ-SIGNATURE-BASELINE-APPROVAL-v1";
const MAX_FRAME_BYTES: usize = 1_048_576;
const MAX_CONCURRENT_CONNECTIONS: usize = 32;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const KEY_SELF_TEST_MESSAGE: &[u8] =
    b"ASTRA-PQ signature-baseline authority-key startup self-test v1";

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

struct ServiceState {
    authority_id: String,
    active_epoch: u64,
    approved_checkpoint: Digest32,
    governance_bundle: GovernanceBundle,
    governance_state: LocalGovernanceState,
    provider: PqProvider,
    signing_key: SecretBytes,
    signing_public_key: Vec<u8>,
    gateway_public_keys: BTreeMap<String, Vec<u8>>,
    completed_requests: BTreeSet<String>,
}

struct ConnectionPermit {
    active_connections: Arc<AtomicUsize>,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.active_connections.fetch_sub(1, Ordering::AcqRel);
    }
}

impl ServiceState {
    fn load() -> anyhow::Result<Self> {
        let authority_id = required_environment("ASTRA_AUTHORITY_ID")?;
        validate_identifier(&authority_id, "authority identifier")?;
        let governance_path = PathBuf::from(required_environment("ASTRA_GOVERNANCE_BUNDLE")?);
        let signing_secret_path =
            PathBuf::from(required_environment("ASTRA_AUTHORITY_SIGNING_KEY")?);
        let signing_public_path =
            PathBuf::from(required_environment("ASTRA_AUTHORITY_PUBLIC_KEY")?);
        let gateway_key_root =
            PathBuf::from(required_environment("ASTRA_GATEWAY_PUBLIC_KEY_ROOT")?);

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
            checkpoint_is_fresh(
                &governance_state,
                &governance_bundle.checkpoint,
                unix_time()?
            ),
            "governance bundle is stale"
        );

        let signing_key = provider.import_signature_secret_key(
            fs::read(&signing_secret_path)
                .with_context(|| format!("read {}", signing_secret_path.display()))?,
        )?;
        let signing_public_key = fs::read(&signing_public_path)
            .with_context(|| format!("read {}", signing_public_path.display()))?;
        let self_test_signature = provider.sign(&signing_key, KEY_SELF_TEST_MESSAGE)?;
        provider
            .verify(
                &signing_public_key,
                KEY_SELF_TEST_MESSAGE,
                &self_test_signature,
            )
            .context("authority public/private key mismatch")?;

        let gateway_public_keys = ["gateway-a", "gateway-b"]
            .into_iter()
            .map(|gateway_id| {
                let path = gateway_key_root.join(format!("{gateway_id}.pk"));
                let key = fs::read(&path)
                    .with_context(|| format!("read trusted gateway key {}", path.display()))?;
                Ok((gateway_id.to_owned(), key))
            })
            .collect::<anyhow::Result<BTreeMap<_, _>>>()?;

        Ok(Self {
            authority_id,
            active_epoch: governance_bundle.checkpoint.epoch,
            approved_checkpoint: governance_state.checkpoint_hash,
            governance_bundle,
            governance_state,
            provider,
            signing_key,
            signing_public_key,
            gateway_public_keys,
            completed_requests: BTreeSet::new(),
        })
    }

    fn process(
        &mut self,
        signed: &SignedBaselineRequest,
    ) -> anyhow::Result<SignedBaselineApproval> {
        anyhow::ensure!(
            checkpoint_is_fresh(
                &self.governance_state,
                &self.governance_bundle.checkpoint,
                unix_time()?
            ),
            "cached governance checkpoint is stale"
        );
        validate_request(&signed.request, self.active_epoch, self.approved_checkpoint)?;
        validate_identifier(&signed.gateway_id, "gateway identifier")?;
        let gateway_public_key = self
            .gateway_public_keys
            .get(&signed.gateway_id)
            .context("gateway is not enrolled")?;
        let request_message = request_message(&signed.gateway_id, &signed.request)?;
        self.provider
            .verify(gateway_public_key, &request_message, &signed.signature)
            .context("gateway request authentication failed")?;

        let replay_key = serde_json::to_string(&(
            &signed.gateway_id,
            signed.request.run,
            signed.request.invocation_nonce,
        ))?;
        anyhow::ensure!(
            !self.completed_requests.contains(&replay_key),
            "duplicate baseline authorization request"
        );

        let request_hash = hash_domain_separated(REQUEST_HASH_LABEL, &[&request_message]);
        let mut approval = SignedBaselineApproval {
            authority_id: self.authority_id.clone(),
            gateway_id: signed.gateway_id.clone(),
            profile: signed.request.profile.clone(),
            request_hash,
            signature: Vec::new(),
        };
        approval.signature = self
            .provider
            .sign(&self.signing_key, &approval_message(&approval)?)?;
        self.provider
            .verify(
                &self.signing_public_key,
                &approval_message(&approval)?,
                &approval.signature,
            )
            .context("authority approval self-verification failed")?;
        self.completed_requests.insert(replay_key);
        Ok(approval)
    }
}

fn main() -> anyhow::Result<()> {
    let bind_address = required_environment("ASTRA_BASELINE_BIND")?;
    let state = ServiceState::load()?;
    let authority_id = state.authority_id.clone();
    let listener = TcpListener::bind(&bind_address)
        .with_context(|| format!("bind signature baseline service to {bind_address}"))?;
    println!(
        "{}",
        json!({
            "schema": "astra-pq-signature-baseline-service-start-v1",
            "authority_id": state.authority_id,
            "bind": bind_address,
            "active_epoch": state.active_epoch,
            "gateway_authentication": "ML-DSA-65",
            "approval_signature": "ML-DSA-65",
            "lwr_evaluation": false,
            "governance_validation": "off-path-signed-bundle-synthetic-iota-observations",
            "connection_model": "bounded-thread-per-connection",
            "maximum_concurrent_connections": MAX_CONCURRENT_CONNECTIONS,
            "replay_state": "in-memory",
            "request_state_serialization": "mutex-protected"
        })
    );

    let shared_state = Arc::new(Mutex::new(state));
    let active_connections = Arc::new(AtomicUsize::new(0));
    for connection in listener.incoming() {
        match connection {
            Ok(mut stream) => {
                let Some(connection_permit) = reserve_connection(&active_connections) else {
                    eprintln!(
                        "{}",
                        json!({
                            "schema": "astra-pq-signature-baseline-capacity-rejection-v1",
                            "authority_id": authority_id,
                            "maximum_concurrent_connections": MAX_CONCURRENT_CONNECTIONS
                        })
                    );
                    continue;
                };
                let connection_state = Arc::clone(&shared_state);
                let connection_authority = authority_id.clone();
                let thread_name = format!("astra-baseline-{connection_authority}-connection");
                if let Err(error) = thread::Builder::new().name(thread_name).spawn(move || {
                    let _connection_permit = connection_permit;
                    if let Err(error) = handle_connection(&mut stream, &connection_state) {
                        eprintln!(
                            "{}",
                            json!({
                                "schema": "astra-pq-signature-baseline-service-error-v1",
                                "authority_id": connection_authority,
                                "error": error.to_string()
                            })
                        );
                    }
                }) {
                    eprintln!(
                        "{}",
                        json!({
                            "schema": "astra-pq-signature-baseline-thread-error-v1",
                            "authority_id": authority_id,
                            "error": error.to_string()
                        })
                    );
                }
            }
            Err(error) => eprintln!(
                "{}",
                json!({
                    "schema": "astra-pq-signature-baseline-accept-error-v1",
                    "authority_id": authority_id,
                    "error": error.to_string()
                })
            ),
        }
    }
    Ok(())
}

fn handle_connection(
    stream: &mut TcpStream,
    state: &Arc<Mutex<ServiceState>>,
) -> anyhow::Result<()> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    loop {
        let Some(encoded_request) = read_frame_or_eof(stream)? else {
            return Ok(());
        };
        let signed: SignedBaselineRequest =
            serde_json::from_slice(&encoded_request).context("decode signed baseline request")?;
        let start = Instant::now();
        let (authority_id, result) = {
            let mut locked_state = state
                .lock()
                .map_err(|_| anyhow::anyhow!("baseline service state mutex is poisoned"))?;
            let authority_id = locked_state.authority_id.clone();
            let result = locked_state.process(&signed);
            (authority_id, result)
        };
        let processing_us = start.elapsed().as_micros();
        let response = match result {
            Ok(approval) => BaselineWireResponse {
                schema: WIRE_SCHEMA.to_owned(),
                authority_id: authority_id.clone(),
                success: true,
                approval: Some(approval),
                error: None,
                processing_us,
            },
            Err(error) => BaselineWireResponse {
                schema: WIRE_SCHEMA.to_owned(),
                authority_id,
                success: false,
                approval: None,
                error: Some(error.to_string()),
                processing_us,
            },
        };
        write_frame(stream, &serde_json::to_vec(&response)?)?;
    }
}

fn validate_request(
    request: &BaselineAuthorizationRequest,
    active_epoch: u64,
    approved_checkpoint: Digest32,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        request.protocol_version == PROTOCOL_VERSION,
        "unsupported protocol version"
    );
    anyhow::ensure!(
        matches!(request.profile.as_str(), "centralized" | "static-quorum"),
        "unsupported signature baseline profile"
    );
    anyhow::ensure!(request.run > 0, "run must be positive");
    anyhow::ensure!(
        !request.invocation_nonce.is_zero(),
        "invocation nonce must not be zero"
    );
    anyhow::ensure!(request.epoch == active_epoch, "governance epoch mismatch");
    anyhow::ensure!(
        request.checkpoint_hash == approved_checkpoint,
        "governance checkpoint mismatch"
    );
    for (value, description) in [
        (&request.source_domain, "source domain"),
        (&request.destination_domain, "destination domain"),
        (&request.subject, "subject"),
        (&request.resource, "resource"),
        (&request.action, "action"),
    ] {
        validate_identifier(value, description)?;
    }
    Ok(())
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

fn reserve_connection(active_connections: &Arc<AtomicUsize>) -> Option<ConnectionPermit> {
    active_connections
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            (current < MAX_CONCURRENT_CONNECTIONS).then_some(current + 1)
        })
        .ok()?;
    Some(ConnectionPermit {
        active_connections: Arc::clone(active_connections),
    })
}

fn read_frame_or_eof(stream: &mut TcpStream) -> anyhow::Result<Option<Vec<u8>>> {
    let mut length_bytes = [0_u8; 4];
    if stream.read(&mut length_bytes[..1])? == 0 {
        return Ok(None);
    }
    stream.read_exact(&mut length_bytes[1..])?;
    let length = usize::try_from(u32::from_be_bytes(length_bytes))
        .context("frame length does not fit this platform")?;
    anyhow::ensure!(
        (1..=MAX_FRAME_BYTES).contains(&length),
        "invalid baseline request length"
    );
    let mut encoded = vec![0_u8; length];
    stream.read_exact(&mut encoded)?;
    Ok(Some(encoded))
}

fn write_frame(stream: &mut TcpStream, encoded: &[u8]) -> anyhow::Result<()> {
    anyhow::ensure!(
        (1..=MAX_FRAME_BYTES).contains(&encoded.len()),
        "invalid baseline response length"
    );
    let length = u32::try_from(encoded.len()).context("baseline response frame is too large")?;
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

    fn request(profile: &str) -> BaselineAuthorizationRequest {
        BaselineAuthorizationRequest {
            protocol_version: PROTOCOL_VERSION,
            profile: profile.to_owned(),
            run: 1,
            invocation_nonce: Digest32::from_bytes([1; 32]),
            epoch: 1,
            checkpoint_hash: Digest32::from_bytes([2; 32]),
            source_domain: "domain-a".to_owned(),
            destination_domain: "domain-b".to_owned(),
            subject: "synthetic-operator".to_owned(),
            resource: "synthetic-plc:4".to_owned(),
            action: "synthetic-safety-actuation".to_owned(),
        }
    }

    #[test]
    fn supported_profiles_are_accepted() {
        let checkpoint = Digest32::from_bytes([2; 32]);
        assert!(validate_request(&request("centralized"), 1, checkpoint).is_ok());
        assert!(validate_request(&request("static-quorum"), 1, checkpoint).is_ok());
    }

    #[test]
    fn unsupported_profile_is_rejected() {
        assert!(validate_request(&request("astra-pq"), 1, Digest32::from_bytes([2; 32])).is_err());
    }

    #[test]
    fn request_message_is_gateway_and_profile_bound() {
        let first = request_message("gateway-a", &request("centralized")).unwrap();
        let changed_gateway = request_message("gateway-b", &request("centralized")).unwrap();
        let changed_profile = request_message("gateway-a", &request("static-quorum")).unwrap();
        assert_ne!(first, changed_gateway);
        assert_ne!(first, changed_profile);
    }
}
