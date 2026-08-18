//! Authenticated TCP authority service for the ASTRA-PQ VM evaluation.
//!
//! The service accepts bounded length-prefixed JSON requests authenticated by
//! an enrolled gateway using ML-DSA-65. It returns signed LWR partial evidence.
//! This lab transport does not provide confidentiality and must carry only
//! synthetic experiment identifiers on the isolated experiment network.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use anyhow::Context;
use astra_authority::{
    AuthorityConfig, AuthorityEngine, SignedAuthorityRequest, SignedPartialEvidence,
    verify_authority_request, verify_evidence,
};
use astra_common::Digest32;
use astra_dprf::lwr::{LwrExactCoalitionBackend, LwrExactCoalitionShare};
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
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const WIRE_SCHEMA: &str = "astra-pq-authority-wire-v1";
const MAX_FRAME_BYTES: usize = 1_048_576;
const MAX_CONCURRENT_CONNECTIONS: usize = 32;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const KEY_SELF_TEST_MESSAGE: &[u8] = b"ASTRA-PQ authority signing-key startup self-test v1";

#[derive(Debug, Serialize, Deserialize)]
struct AuthorityWireResponse {
    schema: String,
    authority_id: String,
    success: bool,
    evidence: Option<SignedPartialEvidence>,
    error: Option<String>,
    processing_us: u128,
}

struct ServiceState {
    authority_id: String,
    active_epoch: u64,
    share_version: u64,
    approved_checkpoint: Digest32,
    governance_bundle: GovernanceBundle,
    governance_state: LocalGovernanceState,
    provider: PqProvider,
    backend: LwrExactCoalitionBackend,
    signing_key: SecretBytes,
    signing_public_key: Vec<u8>,
    gateway_public_keys: BTreeMap<String, Vec<u8>>,
    shares: BTreeMap<String, LwrExactCoalitionShare>,
    completed_sessions: BTreeSet<String>,
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
        let share_version = required_u64("ASTRA_SHARE_VERSION")?;
        let governance_path = PathBuf::from(required_environment("ASTRA_GOVERNANCE_BUNDLE")?);
        let share_root = PathBuf::from(required_environment("ASTRA_LWR_SHARE_ROOT")?);
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
        let active_epoch = governance_bundle.checkpoint.epoch;
        let approved_checkpoint = governance_state.checkpoint_hash;

        let secret_bytes = fs::read(&signing_secret_path)
            .with_context(|| format!("read {}", signing_secret_path.display()))?;
        let signing_key = provider
            .import_signature_secret_key(secret_bytes)
            .context("import authority signing key")?;
        let signing_public_key = fs::read(&signing_public_path)
            .with_context(|| format!("read {}", signing_public_path.display()))?;
        let self_test_signature = provider
            .sign(&signing_key, KEY_SELF_TEST_MESSAGE)
            .context("authority signing-key self-test")?;
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
        let shares = load_shares(&share_root, &authority_id)?;
        anyhow::ensure!(
            !shares.is_empty(),
            "authority has no provisioned LWR shares"
        );

        Ok(Self {
            authority_id,
            active_epoch,
            share_version,
            approved_checkpoint,
            governance_bundle,
            governance_state,
            provider,
            backend: LwrExactCoalitionBackend,
            signing_key,
            signing_public_key,
            gateway_public_keys,
            shares,
            completed_sessions: BTreeSet::new(),
        })
    }

    fn process(
        &mut self,
        signed: &SignedAuthorityRequest,
    ) -> anyhow::Result<SignedPartialEvidence> {
        anyhow::ensure!(
            checkpoint_is_fresh(
                &self.governance_state,
                &self.governance_bundle.checkpoint,
                unix_time()?
            ),
            "cached governance checkpoint is stale"
        );
        let gateway_public_key = self
            .gateway_public_keys
            .get(&signed.gateway_id)
            .context("gateway is not enrolled")?;
        verify_authority_request(&self.provider, gateway_public_key, signed)
            .context("gateway request authentication failed")?;
        let request = &signed.request;
        let share = self
            .shares
            .get(&request.evaluation.clause_id)
            .context("authority is not provisioned for this exact coalition")?;
        let replay_key = format!(
            "{}:{}:{}",
            request.context.session_id,
            request.evaluation.clause_id,
            request.evaluation.share_version
        );
        anyhow::ensure!(
            !self.completed_sessions.contains(&replay_key),
            "duplicate session-clause request"
        );
        let config = AuthorityConfig {
            authority_id: self.authority_id.clone(),
            active_epoch: self.active_epoch,
            share_version: self.share_version,
            approved_checkpoint: self.approved_checkpoint,
            allowed_clauses: BTreeSet::from([request.evaluation.clause_id.clone()]),
        };
        let mut engine = AuthorityEngine::new(
            config,
            &self.backend,
            share,
            &self.provider,
            &self.signing_key,
        );
        let evidence = engine
            .authorize(request)
            .context("authority request rejected")?;
        verify_evidence(
            &self.provider,
            &self.signing_public_key,
            &request.context,
            &evidence,
        )
        .context("authority evidence self-verification failed")?;
        self.completed_sessions.insert(replay_key);
        Ok(evidence)
    }
}

fn main() -> anyhow::Result<()> {
    let bind_address = required_environment("ASTRA_AUTHORITY_BIND")?;
    let state = ServiceState::load()?;
    let authority_id = state.authority_id.clone();
    let provisioned_thresholds: BTreeSet<u16> = state
        .shares
        .keys()
        .filter_map(|clause_id| parse_threshold(clause_id).ok())
        .collect();
    let listener = TcpListener::bind(&bind_address)
        .with_context(|| format!("bind authority service to {bind_address}"))?;
    println!(
        "{}",
        json!({
            "schema": "astra-pq-authority-service-start-v1",
            "authority_id": state.authority_id,
            "bind": bind_address,
            "provisioned_thresholds": provisioned_thresholds,
            "provisioned_coalitions": state.shares.len(),
            "active_epoch": state.active_epoch,
            "share_version": state.share_version,
            "gateway_authentication": "ML-DSA-65",
            "evidence_signature": "ML-DSA-65",
            "replay_state": "in-memory",
            "connection_model": "bounded-thread-per-connection",
            "maximum_concurrent_connections": MAX_CONCURRENT_CONNECTIONS,
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
                            "schema": "astra-pq-authority-capacity-rejection-v1",
                            "authority_id": authority_id,
                            "maximum_concurrent_connections": MAX_CONCURRENT_CONNECTIONS
                        })
                    );
                    continue;
                };
                let connection_state = Arc::clone(&shared_state);
                let connection_authority = authority_id.clone();
                let thread_name = format!("astra-{connection_authority}-connection");
                if let Err(error) = thread::Builder::new().name(thread_name).spawn(move || {
                    let _connection_permit = connection_permit;
                    if let Err(error) = handle_connection(&mut stream, &connection_state) {
                        eprintln!(
                            "{}",
                            json!({
                                "schema": "astra-pq-authority-service-error-v1",
                                "authority_id": connection_authority,
                                "error": error.to_string()
                            })
                        );
                    }
                }) {
                    eprintln!(
                        "{}",
                        json!({
                            "schema": "astra-pq-authority-thread-error-v1",
                            "authority_id": authority_id,
                            "error": error.to_string()
                        })
                    );
                }
            }
            Err(error) => eprintln!(
                "{}",
                json!({
                    "schema": "astra-pq-authority-accept-error-v1",
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
        let signed: SignedAuthorityRequest =
            serde_json::from_slice(&encoded_request).context("decode signed authority request")?;
        let start = Instant::now();
        let (authority_id, result) = {
            let mut locked_state = state
                .lock()
                .map_err(|_| anyhow::anyhow!("authority state mutex is poisoned"))?;
            let authority_id = locked_state.authority_id.clone();
            let result = locked_state.process(&signed);
            (authority_id, result)
        };
        let processing_us = start.elapsed().as_micros();
        let response = match result {
            Ok(evidence) => AuthorityWireResponse {
                schema: WIRE_SCHEMA.to_owned(),
                authority_id: authority_id.clone(),
                success: true,
                evidence: Some(evidence),
                error: None,
                processing_us,
            },
            Err(error) => AuthorityWireResponse {
                schema: WIRE_SCHEMA.to_owned(),
                authority_id,
                success: false,
                evidence: None,
                error: Some(error.to_string()),
                processing_us,
            },
        };
        let encoded_response = serde_json::to_vec(&response)?;
        write_frame(stream, &encoded_response)?;
    }
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
        "invalid authority frame length"
    );
    let mut encoded = vec![0_u8; length];
    stream.read_exact(&mut encoded)?;
    Ok(Some(encoded))
}

fn write_frame(stream: &mut TcpStream, encoded: &[u8]) -> anyhow::Result<()> {
    anyhow::ensure!(
        (1..=MAX_FRAME_BYTES).contains(&encoded.len()),
        "invalid authority response length"
    );
    let length = u32::try_from(encoded.len()).context("response frame is too large")?;
    let mut frame = Vec::with_capacity(4 + encoded.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(encoded);
    stream.write_all(&frame)?;
    stream.flush()?;
    Ok(())
}

fn load_shares(
    root: &Path,
    authority_id: &str,
) -> anyhow::Result<BTreeMap<String, LwrExactCoalitionShare>> {
    let mut shares = BTreeMap::new();
    let mut share_paths = Vec::new();
    collect_share_paths(root, &mut share_paths)?;
    share_paths.sort();
    for path in share_paths {
        let encoded = Zeroizing::new(
            fs::read(&path).with_context(|| format!("read LWR share {}", path.display()))?,
        );
        let share = LwrExactCoalitionShare::import_lab_provisioning(&encoded)
            .with_context(|| format!("import LWR share {}", path.display()))?;
        anyhow::ensure!(
            share.authority_id() == authority_id,
            "provisioned LWR share belongs to another authority"
        );
        let clause_id = share.clause_id().to_owned();
        let (_, clause_members) = parse_coalition_clause(&clause_id)
            .context("provisioned LWR share has an unsupported coalition clause")?;
        let share_members: Vec<&str> = share.coalition().iter().map(String::as_str).collect();
        anyhow::ensure!(
            clause_members == share_members,
            "provisioned LWR share coalition differs from its clause identifier"
        );
        anyhow::ensure!(
            shares.insert(clause_id.clone(), share).is_none(),
            "duplicate provisioned coalition clause {clause_id}"
        );
    }
    Ok(shares)
}

fn collect_share_paths(root: &Path, paths: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    for entry in fs::read_dir(root)
        .with_context(|| format!("read LWR share directory {}", root.display()))?
    {
        let entry = entry.with_context(|| format!("read entry under {}", root.display()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .with_context(|| format!("inspect LWR provisioning path {}", path.display()))?;
        if file_type.is_dir() {
            collect_share_paths(&path, paths)?;
        } else if file_type.is_file()
            && path.extension().and_then(|extension| extension.to_str()) == Some("lwr")
        {
            paths.push(path);
        }
    }
    Ok(())
}

fn parse_threshold(clause_id: &str) -> anyhow::Result<u16> {
    Ok(parse_coalition_clause(clause_id)?.0)
}

fn parse_coalition_clause(clause_id: &str) -> anyhow::Result<(u16, Vec<&str>)> {
    let suffix = clause_id
        .strip_prefix("distributed-t")
        .context("unsupported distributed clause identifier")?;
    let (threshold, coalition) = suffix
        .split_once("-c-")
        .context("distributed clause lacks an exact coalition identifier")?;
    anyhow::ensure!(
        !coalition.is_empty(),
        "distributed coalition identifier is empty"
    );
    let value = threshold
        .parse::<u16>()
        .context("invalid distributed threshold")?;
    anyhow::ensure!((1..=7).contains(&value), "threshold is outside lab bounds");
    let members: Vec<&str> = coalition.split('-').collect();
    anyhow::ensure!(
        members.len() == usize::from(value),
        "coalition size differs from threshold"
    );
    let mut previous_index = 0_u16;
    for member in &members {
        let index = member
            .strip_prefix('a')
            .context("invalid coalition authority identifier")?
            .parse::<u16>()
            .context("invalid coalition authority index")?;
        anyhow::ensure!(
            (1..=7).contains(&index) && index > previous_index,
            "coalition authorities are invalid, duplicated, or unsorted"
        );
        previous_index = index;
    }
    Ok((value, members))
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

fn required_u64(name: &str) -> anyhow::Result<u64> {
    let value = required_environment(name)?
        .parse::<u64>()
        .with_context(|| format!("parse {name} as an integer"))?;
    anyhow::ensure!(value > 0, "{name} must be positive");
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
    fn coalition_clause_parser_accepts_canonical_identifier() {
        let (threshold, members) = parse_coalition_clause("distributed-t3-c-a1-a4-a7").unwrap();
        assert_eq!(threshold, 3);
        assert_eq!(members, vec!["a1", "a4", "a7"]);
    }

    #[test]
    fn coalition_clause_parser_rejects_noncanonical_identifiers() {
        for clause_id in [
            "distributed-t3",
            "distributed-t3-c-a1-a2",
            "distributed-t2-c-a2-a1",
            "distributed-t2-c-a1-a1",
            "distributed-t2-c-a1-a8",
        ] {
            assert!(parse_coalition_clause(clause_id).is_err(), "{clause_id}");
        }
    }

    #[test]
    fn connection_limit_is_enforced_and_released() {
        let active_connections = Arc::new(AtomicUsize::new(0));
        let permits: Vec<ConnectionPermit> = (0..MAX_CONCURRENT_CONNECTIONS)
            .map(|_| reserve_connection(&active_connections).unwrap())
            .collect();
        assert_eq!(
            active_connections.load(Ordering::Acquire),
            MAX_CONCURRENT_CONNECTIONS
        );
        assert!(reserve_connection(&active_connections).is_none());
        drop(permits);
        assert_eq!(active_connections.load(Ordering::Acquire), 0);
    }
}
