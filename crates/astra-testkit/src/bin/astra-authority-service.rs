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
use astra_common::{Digest32, RiskClass};
use astra_dprf::lwr::{LwrExactCoalitionBackend, LwrExactCoalitionShare};
use astra_governance::{
    GovernanceBundle, LocalGovernanceState, checkpoint_hash, checkpoint_is_fresh, validate_bundle,
};
use astra_pqcrypto::{PqProvider, SecretBytes};
use astra_testkit::replay_store::ReplayStore;
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
    replay_store: ReplayStore,
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
        let replay_db_path = PathBuf::from(required_environment("ASTRA_AUTHORITY_REPLAY_DB")?);
        let provider = PqProvider::new().context("initialize post-quantum provider")?;

        let mut replay_store = ReplayStore::open(&replay_db_path).with_context(|| {
            format!(
                "open durable authority replay database {}",
                replay_db_path.display()
            )
        })?;

        replay_store
            .cleanup_expired(unix_time()?)
            .context("clean expired authority replay state")?;

        let governance_bundle: GovernanceBundle = serde_json::from_slice(
            &fs::read(&governance_path)
                .with_context(|| format!("read {}", governance_path.display()))?,
        )
        .context("decode governance bundle")?;

        let governance_scope = format!("authority:{}", authority_id);
        let governance_now = unix_time()?;

        let persisted_governance = replay_store
            .load_governance_state(&governance_scope)
            .context("load durable authority governance state")?;

        let candidate_checkpoint_hash = checkpoint_hash(&governance_bundle.checkpoint)
            .context("hash authority governance checkpoint")?;

        let (governance_state, governance_changed) = match persisted_governance {
            None => {
                let state = validate_bundle(
                    &provider,
                    &LocalGovernanceState::default(),
                    &governance_bundle,
                    governance_now,
                )
                .context("validate initial off-path governance bundle")?;

                (state, true)
            }

            Some(current) if governance_bundle.checkpoint.epoch == current.highest_epoch => {
                anyhow::ensure!(
                    candidate_checkpoint_hash == current.checkpoint_hash,
                    "persisted governance checkpoint conflicts with loaded bundle"
                );

                anyhow::ensure!(
                    governance_bundle.anchor.epoch == current.highest_epoch,
                    "persisted governance epoch conflicts with loaded ledger anchor"
                );

                anyhow::ensure!(
                    governance_bundle.anchor.checkpoint_hash == current.checkpoint_hash,
                    "persisted governance checkpoint conflicts with loaded ledger anchor"
                );

                anyhow::ensure!(
                    governance_bundle.anchor.object_version == current.object_version,
                    "persisted governance object version conflicts with loaded ledger anchor"
                );

                (current, false)
            }

            Some(current) => {
                let state =
                    validate_bundle(&provider, &current, &governance_bundle, governance_now)
                        .context(
                            "validate governance bundle against durable authority high-water state",
                        )?;

                (state, true)
            }
        };

        anyhow::ensure!(
            checkpoint_is_fresh(
                &governance_state,
                &governance_bundle.checkpoint,
                governance_now
            ),
            "governance bundle is stale"
        );

        if governance_changed {
            replay_store
                .store_governance_state(&governance_scope, &governance_state)
                .context("persist authority governance high-water state")?;
        }

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
            replay_store,
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
        let risk_key = risk_share_key(request.context.risk, &request.evaluation.clause_id);
        let share = self
            .shares
            .get(&risk_key)
            .or_else(|| self.shares.get(&request.evaluation.clause_id))
            .context("authority is not provisioned for this exact coalition")?;
        let replay_scope = format!(
            "authority:{}:{}:{}",
            self.authority_id, request.evaluation.clause_id, request.evaluation.share_version
        );

        let replay_now = unix_time()?;

        request
            .context
            .validate_at(replay_now)
            .context("authority request is outside its validity interval")?;

        self.replay_store
            .cleanup_expired(replay_now)
            .context("clean expired authority replay state")?;

        self.replay_store
            .reserve(
                &replay_scope,
                &request.context.session_id,
                request.context.epoch,
                request.context.expires_at_unix,
                replay_now,
            )
            .context("reserve durable authority replay state")?;

        let processing_result = (|| -> anyhow::Result<SignedPartialEvidence> {
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
                .authorize_at(request, unix_time()?)
                .context("authority request rejected")?;
            verify_evidence(
                &self.provider,
                &self.signing_public_key,
                &request.context,
                &evidence,
            )
            .context("authority evidence self-verification failed")?;
            Ok(evidence)
        })();

        match processing_result {
            Ok(evidence) => {
                self.replay_store
                    .mark_accepted(
                        &replay_scope,
                        &request.context.session_id,
                        request.context.epoch,
                        unix_time()?,
                    )
                    .context("persist accepted authority replay state")?;

                Ok(evidence)
            }
            Err(error) => {
                if let Err(state_error) = self.replay_store.mark_rejected(
                    &replay_scope,
                    &request.context.session_id,
                    request.context.epoch,
                    replay_now,
                ) {
                    return Err(anyhow::anyhow!(
                        "{error:#}; additionally failed to persist rejected replay state: {state_error}"
                    ));
                }

                Err(error)
            }
        }
    }
}

fn main() -> anyhow::Result<()> {
    let bind_address = required_environment("ASTRA_AUTHORITY_BIND")?;
    let state = ServiceState::load()?;
    let authority_id = state.authority_id.clone();
    let provisioned_thresholds: BTreeSet<u16> = state
        .shares
        .keys()
        .filter_map(|storage_key| parse_storage_threshold(storage_key).ok())
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
            "replay_state": "sqlite-wal-durable",
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
            Err(error) => {
                eprintln!(
                    "{}",
                    json!({
                        "schema": "astra-pq-authority-request-rejection-v1",
                        "authority_id": authority_id,
                        "error": format!("{error:#}")
                    })
                );

                AuthorityWireResponse {
                    schema: WIRE_SCHEMA.to_owned(),
                    authority_id,
                    success: false,
                    evidence: None,
                    error: Some("authority request rejected".to_owned()),
                    processing_us,
                }
            }
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
        let (_, clause_members) = parse_provisioned_clause(&path, &clause_id)
            .context("provisioned LWR share has an unsupported clause")?;
        let share_members: Vec<&str> = share.coalition().iter().map(String::as_str).collect();
        anyhow::ensure!(
            clause_members == share_members,
            "provisioned LWR share coalition differs from its clause identifier"
        );
        let storage_key = provisioned_share_key(&path, &clause_id);
        anyhow::ensure!(
            shares.insert(storage_key.clone(), share).is_none(),
            "duplicate provisioned coalition share {storage_key}"
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

fn risk_share_key(risk: RiskClass, clause_id: &str) -> String {
    format!("r{}:{clause_id}", risk.wire_value())
}

fn provisioned_share_key(path: &Path, clause_id: &str) -> String {
    provisioned_risk(path).map_or_else(
        || clause_id.to_owned(),
        |risk| risk_share_key(risk, clause_id),
    )
}

fn provisioned_risk(path: &Path) -> Option<RiskClass> {
    path.components().rev().find_map(|component| {
        let value = component.as_os_str().to_str()?;
        parse_risk_directory(value)
    })
}

fn parse_risk_directory(value: &str) -> Option<RiskClass> {
    match value {
        "r0" => Some(RiskClass::R0),
        "r1" => Some(RiskClass::R1),
        "r2" => Some(RiskClass::R2),
        "r3" => Some(RiskClass::R3),
        "r4" => Some(RiskClass::R4),
        _ => None,
    }
}

fn parse_provisioned_clause(
    path: &Path,
    clause_id: &str,
) -> anyhow::Result<(u16, Vec<&'static str>)> {
    match provisioned_risk(path) {
        Some(risk) => parse_risk_clause(risk, clause_id),
        None => {
            let (threshold, members) = parse_supported_clause(clause_id)?;
            let members = members
                .into_iter()
                .map(|member| match member {
                    "a1" => "a1",
                    "a2" => "a2",
                    "a3" => "a3",
                    "a4" => "a4",
                    "a5" => "a5",
                    "a6" => "a6",
                    "a7" => "a7",
                    _ => unreachable!("validated authority identifier"),
                })
                .collect();
            Ok((threshold, members))
        }
    }
}

fn parse_risk_clause(risk: RiskClass, clause_id: &str) -> anyhow::Result<(u16, Vec<&'static str>)> {
    match (risk, clause_id) {
        (RiskClass::R0, "destination") => Ok((1, vec!["a2"])),
        (RiskClass::R1, "destination") | (RiskClass::R2, "destination") => Ok((1, vec!["a2"])),
        (RiskClass::R1, "risk-floor") | (RiskClass::R2, "risk-floor") => Ok((2, vec!["a1", "a2"])),
        (RiskClass::R2, "source-or-oversight") => Ok((1, vec!["a1"])),
        (RiskClass::R3, "destination") | (RiskClass::R4, "destination") => Ok((1, vec!["a2"])),
        (RiskClass::R3, "risk-floor") => Ok((3, vec!["a1", "a2", "a3"])),
        (RiskClass::R3, "source") | (RiskClass::R4, "source") => Ok((1, vec!["a1"])),
        (RiskClass::R3, "safety") | (RiskClass::R4, "safety") => Ok((1, vec!["a3"])),
        (RiskClass::R4, "risk-floor") => Ok((4, vec!["a1", "a2", "a3", "a4"])),
        (RiskClass::R4, "human-confirmation") => Ok((1, vec!["a4"])),
        _ => anyhow::bail!("clause is not valid for the provisioned risk class"),
    }
}

fn parse_storage_threshold(storage_key: &str) -> anyhow::Result<u16> {
    if let Some((risk, clause_id)) = storage_key.split_once(':') {
        let risk = parse_risk_directory(risk).context("invalid risk-qualified share key")?;
        return Ok(parse_risk_clause(risk, clause_id)?.0);
    }
    parse_threshold(storage_key)
}

fn parse_supported_clause(clause_id: &str) -> anyhow::Result<(u16, Vec<&str>)> {
    match clause_id {
        "destination" => Ok((1, vec!["a2"])),
        "risk-floor" => Ok((3, vec!["a1", "a2", "a3"])),
        "source" => Ok((1, vec!["a1"])),
        "safety" => Ok((1, vec!["a3"])),
        "source-or-oversight" => Ok((1, vec!["a1"])),
        "human-confirmation" => Ok((1, vec!["a4"])),
        _ => parse_coalition_clause(clause_id),
    }
}

fn parse_threshold(clause_id: &str) -> anyhow::Result<u16> {
    Ok(parse_supported_clause(clause_id)?.0)
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
    fn normative_session_clauses_have_explicit_coalitions() {
        assert_eq!(
            parse_supported_clause("destination").unwrap(),
            (1, vec!["a2"])
        );
        assert_eq!(
            parse_supported_clause("risk-floor").unwrap(),
            (3, vec!["a1", "a2", "a3"])
        );
        assert_eq!(parse_supported_clause("source").unwrap(), (1, vec!["a1"]));
        assert_eq!(parse_supported_clause("safety").unwrap(), (1, vec!["a3"]));
        assert!(parse_supported_clause("unsupported-session-clause").is_err());
    }

    #[test]
    fn adaptive_share_keys_are_risk_qualified() {
        let path = Path::new("/lab/adaptive-session/r4/risk-floor/a4.lwr");
        assert_eq!(provisioned_share_key(path, "risk-floor"), "r4:risk-floor");
        assert_eq!(
            parse_provisioned_clause(path, "risk-floor").unwrap(),
            (4, vec!["a1", "a2", "a3", "a4"])
        );
        assert_eq!(parse_storage_threshold("r4:risk-floor").unwrap(), 4);
    }

    #[test]
    fn adaptive_risk_clauses_are_strictly_scoped() {
        assert_eq!(
            parse_risk_clause(RiskClass::R1, "risk-floor").unwrap(),
            (2, vec!["a1", "a2"])
        );
        assert_eq!(
            parse_risk_clause(RiskClass::R2, "source-or-oversight").unwrap(),
            (1, vec!["a1"])
        );
        assert!(parse_risk_clause(RiskClass::R1, "source").is_err());
        assert!(parse_risk_clause(RiskClass::R3, "human-confirmation").is_err());
    }

    #[test]
    fn generic_share_keys_remain_backward_compatible() {
        let path = Path::new("/lab/session-policy/risk-floor.lwr");
        assert_eq!(provisioned_share_key(path, "risk-floor"), "risk-floor");
        assert_eq!(parse_storage_threshold("risk-floor").unwrap(), 3);
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
