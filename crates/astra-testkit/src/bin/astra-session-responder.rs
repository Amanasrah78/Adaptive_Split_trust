//! Gateway B service for the distributed ASTRA-PQ dual-gate handshake.
//!
//! The service verifies an ML-DSA-authenticated Gateway A request, validates
//! all governed risk-adaptive authorization evidence, decapsulates ML-KEM-768, derives
//! the session key locally, and completes explicit bidirectional key
//! confirmation. Session keys and intermediate secrets are never serialized.

#![forbid(unsafe_code)]
#![recursion_limit = "256"]
#![warn(missing_docs)]

use anyhow::Context;
use astra_common::{Digest32, RiskClass};
use astra_dprf::lwr::LwrExactCoalitionBackend;
use astra_gateway::{AuthorityVerificationKeys, SessionEstablishmentRequest, establish_session};
use astra_governance::{
    GovernanceBundle, GovernanceProfile, LocalGovernanceState, checkpoint_hash,
    checkpoint_is_fresh, validate_bundle,
};
use astra_pqcrypto::{
    ConfirmationRole, PqProvider, SecretBytes, derive_session_confirmation_tag,
    record::{RecordContentType, RecordDirection, RecordReceiver, RecordSender},
};
use astra_testkit::adaptive_lab_synthesis;
use astra_testkit::replay_store::ReplayStore;
use astra_testkit::session_wire::{
    MAX_GATEWAY_MESSAGE_BYTES, SESSION_COMPLETION_SCHEMA, SESSION_FINISH_SCHEMA,
    SESSION_RESPONSE_SCHEMA, SessionHandshakeCompletion, SessionHandshakeFinish,
    SessionHandshakeResponse, SignedSessionHandshakeFinish, SignedSessionHandshakeRequest,
    request_transcript_hash, sign_session_completion, sign_session_response, verify_session_finish,
    verify_session_request,
};
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_CONCURRENT_CONNECTIONS: usize = 32;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const RESPONDER_ID: &str = "gateway-b";
const SIGNING_SELF_TEST_MESSAGE: &[u8] = b"ASTRA-PQ responder signing-key self-test v1";
const LIVE_IOTA_NETWORK_ID: &str = "2304aa97";
const LIVE_IOTA_PACKAGE_ID: &str =
    "0x7e3cd4ec241a0a3ac81d79bb08b6d6873e928bca41354b6f6b2c13d1e0b499f6";
const LIVE_IOTA_OBJECT_ID: &str =
    "0x6035354dc7c2334715d0e2f773e90ca59920ac352faeded383f8e7aba0edeb2e";
const LIVE_IOTA_PACKAGE_VERSION: u64 = 1;

struct ResponderState {
    provider: PqProvider,
    backend: LwrExactCoalitionBackend,
    governance_bundle: GovernanceBundle,
    governance_state: LocalGovernanceState,
    kem_secret_key: SecretBytes,
    responder_signing_key: SecretBytes,
    initiator_verification_key: Vec<u8>,
    authority_verification_keys: AuthorityVerificationKeys,
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

impl ResponderState {
    fn load() -> anyhow::Result<Self> {
        let governance_path = required_path("ASTRA_GOVERNANCE_BUNDLE")?;
        let kem_secret_path = required_path("ASTRA_RESPONDER_KEM_SECRET")?;
        let kem_public_path = required_path("ASTRA_RESPONDER_KEM_PUBLIC")?;
        let signing_secret_path = required_path("ASTRA_RESPONDER_SIGNING_KEY")?;
        let signing_public_path = required_path("ASTRA_RESPONDER_SIGNING_PUBLIC_KEY")?;
        let initiator_public_path = required_path("ASTRA_INITIATOR_PUBLIC_KEY")?;
        let authority_key_root = required_path("ASTRA_AUTHORITY_PUBLIC_KEY_ROOT")?;
        let replay_db_path = required_path("ASTRA_RESPONDER_REPLAY_DB")?;
        let provider = PqProvider::new().context("initialize post-quantum provider")?;

        let mut replay_store = ReplayStore::open(&replay_db_path).with_context(|| {
            format!(
                "open durable responder replay database {}",
                replay_db_path.display()
            )
        })?;

        replay_store
            .cleanup_expired(unix_time()?)
            .context("clean expired responder replay state")?;

        let governance_bundle: GovernanceBundle = serde_json::from_slice(
            &fs::read(&governance_path)
                .with_context(|| format!("read {}", governance_path.display()))?,
        )
        .context("decode governance bundle")?;

        let governance_scope = "responder";
        let governance_now = unix_time()?;

        let persisted_governance = replay_store
            .load_governance_state(governance_scope)
            .context("load durable responder governance state")?;

        let candidate_checkpoint_hash = checkpoint_hash(&governance_bundle.checkpoint)
            .context("hash responder governance checkpoint")?;

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
                            "validate governance bundle against durable responder high-water state",
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
                .store_governance_state(governance_scope, &governance_state)
                .context("persist responder governance high-water state")?;
        }

        let kem_secret_key = provider.import_kem_secret_key(
            fs::read(&kem_secret_path)
                .with_context(|| format!("read {}", kem_secret_path.display()))?,
        )?;
        let kem_public_key = fs::read(&kem_public_path)
            .with_context(|| format!("read {}", kem_public_path.display()))?;
        let kem_self_test = provider
            .encapsulate(&kem_public_key)
            .context("encapsulate responder KEM self-test")?;
        let kem_recovered = provider
            .decapsulate(&kem_secret_key, kem_self_test.ciphertext())
            .context("decapsulate responder KEM self-test")?;
        anyhow::ensure!(
            secrets_equal(
                kem_self_test.shared_secret().expose_secret(),
                kem_recovered.expose_secret()
            ),
            "responder KEM public/private key mismatch"
        );

        let responder_signing_key = provider.import_signature_secret_key(
            fs::read(&signing_secret_path)
                .with_context(|| format!("read {}", signing_secret_path.display()))?,
        )?;
        let responder_signing_public = fs::read(&signing_public_path)
            .with_context(|| format!("read {}", signing_public_path.display()))?;
        let self_test_signature = provider
            .sign(&responder_signing_key, SIGNING_SELF_TEST_MESSAGE)
            .context("responder signing-key self-test")?;
        provider
            .verify(
                &responder_signing_public,
                SIGNING_SELF_TEST_MESSAGE,
                &self_test_signature,
            )
            .context("responder signing public/private key mismatch")?;

        let initiator_verification_key = fs::read(&initiator_public_path)
            .with_context(|| format!("read {}", initiator_public_path.display()))?;
        let authority_verification_keys = ["a1", "a2", "a3", "a4"]
            .into_iter()
            .map(|authority| {
                let path = authority_key_root.join(format!("{authority}.pk"));
                let key = fs::read(&path)
                    .with_context(|| format!("read authority key {}", path.display()))?;
                Ok((authority.to_owned(), key))
            })
            .collect::<anyhow::Result<BTreeMap<_, _>>>()?;

        Ok(Self {
            provider,
            backend: LwrExactCoalitionBackend,
            governance_bundle,
            governance_state,
            kem_secret_key,
            responder_signing_key,
            initiator_verification_key,
            authority_verification_keys,
            replay_store,
        })
    }
}

const PROTECTED_APPLICATION_REQUEST: &[u8] = b"ASTRA-PQ protected application request v1";
const PROTECTED_APPLICATION_RESPONSE: &[u8] = b"ASTRA-PQ protected application response v1";

fn main() -> anyhow::Result<()> {
    let bind_address = required_environment("ASTRA_SESSION_RESPONDER_BIND")?;
    let state = ResponderState::load()?;
    let metadata = state.provider.metadata();
    let listener = TcpListener::bind(&bind_address)
        .with_context(|| format!("bind session responder to {bind_address}"))?;
    println!(
        "{}",
        json!({
            "schema": "astra-pq-session-responder-start-v1",
            "gateway_id": RESPONDER_ID,
            "bind": bind_address,
            "kem": metadata.kem_algorithm,
            "signature": metadata.signature_algorithm,
            "authorization_policy": "risk-adaptive-exact-coalition-R0-through-R4",
            "evidence_items_by_risk": {"R0": 1, "R1": 3, "R2": 4, "R3": 6, "R4": 8},
            "governance_validation": governance_reporting(&state.governance_bundle.profile).0,
            "live_iota_claim": governance_reporting(&state.governance_bundle.profile).1,
            "governance_network_id": &state.governance_bundle.profile.network_id,
            "governance_package_id": &state.governance_bundle.profile.package_id,
            "governance_object_id": &state.governance_bundle.profile.object_id,
            "governance_object_version": state.governance_bundle.anchor.object_version,
            "rpc_service_observations": state.governance_bundle.observations.len(),
            "rpc_service_quorum": state.governance_bundle.profile.rpc_quorum,
            "rpc_administrative_independence_claim": false,
            "connection_model": "bounded-thread-per-connection",
            "maximum_concurrent_connections": MAX_CONCURRENT_CONNECTIONS,
            "session_processing": "mutex-serialized",
            "replay_state": "sqlite-wal-durable"
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
                            "schema": "astra-pq-session-responder-capacity-rejection-v1",
                            "maximum_concurrent_connections": MAX_CONCURRENT_CONNECTIONS
                        })
                    );
                    continue;
                };
                configure_stream(&stream)?;
                let connection_state = Arc::clone(&shared_state);
                if let Err(error) = thread::Builder::new()
                    .name("astra-session-responder-connection".to_owned())
                    .spawn(move || {
                        let _connection_permit = connection_permit;
                        if let Err(error) = handle_connection(&mut stream, &connection_state) {
                            eprintln!(
                                "{}",
                                json!({
                                    "schema": "astra-pq-session-responder-error-v1",
                                    "error": error.to_string()
                                })
                            );
                        }
                    })
                {
                    eprintln!(
                        "{}",
                        json!({
                            "schema": "astra-pq-session-responder-thread-error-v1",
                            "error": error.to_string()
                        })
                    );
                }
            }
            Err(error) => eprintln!(
                "{}",
                json!({
                    "schema": "astra-pq-session-responder-accept-error-v1",
                    "error": error.to_string()
                })
            ),
        }
    }
    Ok(())
}

fn handle_connection(
    stream: &mut TcpStream,
    shared_state: &Arc<Mutex<ResponderState>>,
) -> anyhow::Result<()> {
    let total_start = Instant::now();
    let signed_request: SignedSessionHandshakeRequest = read_json_frame(stream)?;
    let mut state = shared_state
        .lock()
        .map_err(|_| anyhow::anyhow!("session responder state lock poisoned"))?;

    let request_verification_start = Instant::now();
    let transcript = verify_session_request(
        &state.provider,
        &state.initiator_verification_key,
        &signed_request,
    )?;
    let request_verification_us = request_verification_start.elapsed().as_micros();
    signed_request
        .request
        .context
        .validate_at(unix_time()?)
        .context("session request is outside its validity interval")?;

    let session_id = signed_request.request.context.session_id;

    anyhow::ensure!(
        checkpoint_is_fresh(
            &state.governance_state,
            &state.governance_bundle.checkpoint,
            unix_time()?
        ),
        "cached governance checkpoint is stale"
    );

    let replay_now = unix_time()?;

    state
        .replay_store
        .cleanup_expired(replay_now)
        .context("clean expired responder replay state")?;

    state
        .replay_store
        .reserve(
            "responder",
            &session_id,
            signed_request.request.context.epoch,
            signed_request.request.context.expires_at_unix,
            replay_now,
        )
        .context("reserve durable responder replay state")?;

    let mut replay_accepted = false;

    let processing_result = (|| -> anyhow::Result<(u128, u128, u128)> {
        let expected_synthesis = adaptive_lab_synthesis(&signed_request.request.context)
            .context("synthesize expected risk-adaptive policy")?;
        anyhow::ensure!(
            signed_request.request.synthesis == expected_synthesis,
            "initiator supplied a noncanonical adaptive policy"
        );

        let decapsulation_start = Instant::now();
        let kem_secret = state.provider.decapsulate(
            &state.kem_secret_key,
            &signed_request.request.kem_ciphertext,
        )?;
        let kem_decapsulation_us = decapsulation_start.elapsed().as_micros();

        let establishment_start = Instant::now();
        let established = establish_session(
            &state.provider,
            &state.backend,
            SessionEstablishmentRequest {
                context: &signed_request.request.context,
                synthesis: &signed_request.request.synthesis,
                share_version: signed_request.request.share_version,
                verification_keys: &state.authority_verification_keys,
                evidence: &signed_request.request.evidence,
                kem_secret: &kem_secret,
                authenticated_transcript: &transcript,
                governance_state: &state.governance_state,
                governance_checkpoint: &state.governance_bundle.checkpoint,
                now: unix_time()?,
            },
        )?;
        let session_establishment_us = establishment_start.elapsed().as_micros();
        let transcript_hash = request_transcript_hash(&transcript);
        let responder_confirmation = derive_session_confirmation_tag(
            &established.secrets.responder_confirmation_key,
            &transcript,
            ConfirmationRole::Responder,
        )?;
        let expected_initiator_confirmation = derive_session_confirmation_tag(
            &established.secrets.initiator_confirmation_key,
            &transcript,
            ConfirmationRole::Initiator,
        )?;
        let response = sign_session_response(
            &state.provider,
            &state.responder_signing_key,
            SessionHandshakeResponse {
                schema: SESSION_RESPONSE_SCHEMA.to_owned(),
                session_id,
                request_transcript_hash: transcript_hash,
                authorization_input: established.authorization_input,
                contributors: established.contributors,
                responder_confirmation,
            },
        )?;
        write_json_frame(stream, &response)?;

        let finish_start = Instant::now();
        let signed_finish: SignedSessionHandshakeFinish = read_json_frame(stream)?;
        verify_session_finish(
            &state.provider,
            &state.initiator_verification_key,
            &signed_finish,
        )?;
        let SessionHandshakeFinish {
            schema,
            session_id: finish_session_id,
            request_transcript_hash: finish_transcript_hash,
            initiator_confirmation,
        } = &signed_finish.finish;
        anyhow::ensure!(
            schema == SESSION_FINISH_SCHEMA,
            "session finish schema mismatch"
        );
        anyhow::ensure!(
            *finish_session_id == session_id && *finish_transcript_hash == transcript_hash,
            "session finish binding mismatch"
        );
        anyhow::ensure!(
            digests_equal(initiator_confirmation, &expected_initiator_confirmation),
            "initiator key confirmation failed"
        );
        let finish_verification_us = finish_start.elapsed().as_micros();

        let completion = sign_session_completion(
            &state.provider,
            &state.responder_signing_key,
            SessionHandshakeCompletion {
                schema: SESSION_COMPLETION_SCHEMA.to_owned(),
                session_id,
                request_transcript_hash: transcript_hash,
                accepted: true,
            },
        )?;

        state
            .replay_store
            .mark_accepted(
                "responder",
                &session_id,
                signed_request.request.context.epoch,
                unix_time()?,
            )
            .context("persist accepted responder replay state")?;

        replay_accepted = true;

        write_json_frame(stream, &completion)?;

        let protected_request = read_raw_frame(stream)?;

        let mut application_receiver = RecordReceiver::new(
            &established.secrets.initiator_write_key,
            &established.secrets.initiator_write_iv,
            session_id,
            RecordDirection::InitiatorToResponder,
            transcript_hash,
        );

        let (request_content_type, request_plaintext) = application_receiver
            .open(&protected_request)
            .context("authenticate initiator application record")?;

        anyhow::ensure!(
            request_content_type == RecordContentType::ApplicationData,
            "unexpected initiator protected-record content type"
        );

        anyhow::ensure!(
            request_plaintext.as_slice() == PROTECTED_APPLICATION_REQUEST,
            "unexpected protected application request"
        );

        let mut application_sender = RecordSender::new(
            &established.secrets.responder_write_key,
            &established.secrets.responder_write_iv,
            session_id,
            RecordDirection::ResponderToInitiator,
            transcript_hash,
        );

        let protected_response = application_sender
            .seal(
                RecordContentType::ApplicationData,
                PROTECTED_APPLICATION_RESPONSE,
            )
            .context("protect responder application record")?;

        write_raw_frame(stream, &protected_response)?;

        Ok((
            kem_decapsulation_us,
            session_establishment_us,
            finish_verification_us,
        ))
    })();

    let (kem_decapsulation_us, session_establishment_us, finish_verification_us) =
        match processing_result {
            Ok(timings) => timings,
            Err(error) => {
                if let Err(state_error) = mark_rejected_before_acceptance(
                    &mut state.replay_store,
                    replay_accepted,
                    &session_id,
                    signed_request.request.context.epoch,
                    replay_now,
                ) {
                    return Err(anyhow::anyhow!(
                        "{error:#}; additionally failed to persist rejected replay state: {state_error}"
                    ));
                }

                return Err(error);
            }
        };

    println!(
        "{}",
        json!({
            "schema": "astra-pq-session-responder-result-v1",
            "success": true,
            "session_id": session_id.to_string(),
            "risk_class": risk_label(signed_request.request.context.risk),
            "clause_count": signed_request.request.synthesis.structure.clauses.len(),
            "evidence_count": signed_request.request.evidence.len(),
            "kem": "ML-KEM-768",
            "signature": "ML-DSA-65",
            "session_key_exported": false,
            "bidirectional_key_confirmation": true,
            "protected_application_data": true,
            "record_cipher": "AES-256-GCM",
            "security_profile": "post-quantum LWR; static corruption; semi-honest; exact coalition",
            "malicious_robust": false,
            "governance_validation": governance_reporting(&state.governance_bundle.profile).0,
            "live_iota_claim": governance_reporting(&state.governance_bundle.profile).1,
            "governance_network_id": &state.governance_bundle.profile.network_id,
            "governance_package_id": &state.governance_bundle.profile.package_id,
            "governance_object_id": &state.governance_bundle.profile.object_id,
            "governance_object_version": state.governance_bundle.anchor.object_version,
            "rpc_service_observations": state.governance_bundle.observations.len(),
            "rpc_service_quorum": state.governance_bundle.profile.rpc_quorum,
            "rpc_administrative_independence_claim": false,
            "timing_us": {
                "request_verification": request_verification_us,
                "kem_decapsulation": kem_decapsulation_us,
                "session_establishment": session_establishment_us,
                "finish_verification": finish_verification_us,
                "total": total_start.elapsed().as_micros()
            }
        })
    );
    Ok(())
}

fn mark_rejected_before_acceptance(
    replay_store: &mut ReplayStore,
    replay_accepted: bool,
    session_id: &astra_common::SessionId,
    epoch: u64,
    now: u64,
) -> anyhow::Result<()> {
    if replay_accepted {
        return Ok(());
    }

    replay_store
        .mark_rejected("responder", session_id, epoch, now)
        .context("persist rejected responder replay state")
}

const fn risk_label(risk: RiskClass) -> &'static str {
    match risk {
        RiskClass::R0 => "R0",
        RiskClass::R1 => "R1",
        RiskClass::R2 => "R2",
        RiskClass::R3 => "R3",
        RiskClass::R4 => "R4",
    }
}

fn configure_stream(stream: &TcpStream) -> anyhow::Result<()> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    Ok(())
}

fn reserve_connection(active: &Arc<AtomicUsize>) -> Option<ConnectionPermit> {
    loop {
        let current = active.load(Ordering::Acquire);
        if current >= MAX_CONCURRENT_CONNECTIONS {
            return None;
        }
        if active
            .compare_exchange_weak(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return Some(ConnectionPermit {
                active_connections: Arc::clone(active),
            });
        }
    }
}

fn read_raw_frame(stream: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
    let mut length_bytes = [0_u8; 4];
    stream.read_exact(&mut length_bytes)?;

    let length = usize::try_from(u32::from_be_bytes(length_bytes))
        .context("frame length does not fit this platform")?;

    anyhow::ensure!(
        (1..=MAX_GATEWAY_MESSAGE_BYTES).contains(&length),
        "invalid gateway frame length"
    );

    let mut encoded = vec![0_u8; length];
    stream.read_exact(&mut encoded)?;

    Ok(encoded)
}

fn write_raw_frame(stream: &mut TcpStream, encoded: &[u8]) -> anyhow::Result<usize> {
    anyhow::ensure!(
        (1..=MAX_GATEWAY_MESSAGE_BYTES).contains(&encoded.len()),
        "invalid gateway frame length"
    );

    let length = u32::try_from(encoded.len()).context("gateway frame is too large")?;

    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(encoded)?;
    stream.flush()?;

    Ok(encoded.len() + 4)
}

fn read_json_frame<T: serde::de::DeserializeOwned>(stream: &mut TcpStream) -> anyhow::Result<T> {
    serde_json::from_slice(&read_raw_frame(stream)?).context("decode gateway frame")
}

fn write_json_frame<T: Serialize>(stream: &mut TcpStream, value: &T) -> anyhow::Result<()> {
    let encoded = serde_json::to_vec(value).context("encode gateway frame")?;
    write_raw_frame(stream, &encoded)?;
    Ok(())
}

fn required_environment(name: &str) -> anyhow::Result<String> {
    let value = env::var(name).with_context(|| format!("missing {name}"))?;
    anyhow::ensure!(!value.trim().is_empty(), "{name} is empty");
    Ok(value)
}

fn required_path(name: &str) -> anyhow::Result<PathBuf> {
    Ok(PathBuf::from(required_environment(name)?))
}

fn unix_time() -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock precedes Unix epoch")?
        .as_secs())
}

fn digests_equal(left: &Digest32, right: &Digest32) -> bool {
    secrets_equal(left.as_bytes(), right.as_bytes())
}

fn secrets_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left_byte, right_byte)| {
            difference | (*left_byte ^ *right_byte)
        })
        == 0
}

fn governance_reporting(profile: &GovernanceProfile) -> (&'static str, bool) {
    let live = profile.network_id == LIVE_IOTA_NETWORK_ID
        && profile.package_id == LIVE_IOTA_PACKAGE_ID
        && profile.object_id == LIVE_IOTA_OBJECT_ID
        && profile.package_version == LIVE_IOTA_PACKAGE_VERSION;

    if live {
        (
            "off-path-signed-bundle-live-iota-testnet-two-service-observation",
            true,
        )
    } else if profile.network_id == "iota-lab-synthetic-observations" {
        ("off-path-signed-bundle-synthetic-iota-observations", false)
    } else {
        ("off-path-signed-bundle-unclassified-observations", false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_replay_database(name: &str) -> PathBuf {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).unwrap();

        std::env::temp_dir().join(format!(
            "astra-pq-responder-{name}-{}.sqlite3",
            random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ))
    }

    fn remove_replay_database(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn post_acceptance_failure_does_not_downgrade_replay_state() {
        use astra_testkit::replay_store::ReplayStatus;

        let path = temporary_replay_database("post-acceptance-failure");

        let session_id = astra_common::SessionId::from_bytes([91; 32]);

        {
            let mut store = ReplayStore::open(&path).unwrap();

            store
                .reserve("responder", &session_id, 2, 300, 100)
                .unwrap();

            store
                .mark_accepted("responder", &session_id, 2, 110)
                .unwrap();

            mark_rejected_before_acceptance(&mut store, true, &session_id, 2, 120).unwrap();

            assert_eq!(
                store.status("responder", &session_id, 2,).unwrap(),
                Some(ReplayStatus::Accepted)
            );
        }

        {
            let restarted = ReplayStore::open(&path).unwrap();

            assert_eq!(
                restarted.status("responder", &session_id, 2,).unwrap(),
                Some(ReplayStatus::Accepted)
            );
        }

        remove_replay_database(&path);
    }

    #[test]
    fn pre_acceptance_failure_is_persisted_as_rejected() {
        use astra_testkit::replay_store::ReplayStatus;

        let path = temporary_replay_database("pre-acceptance-failure");

        let session_id = astra_common::SessionId::from_bytes([92; 32]);

        {
            let mut store = ReplayStore::open(&path).unwrap();

            store
                .reserve("responder", &session_id, 2, 300, 100)
                .unwrap();

            mark_rejected_before_acceptance(&mut store, false, &session_id, 2, 110).unwrap();

            assert_eq!(
                store.status("responder", &session_id, 2,).unwrap(),
                Some(ReplayStatus::Rejected)
            );
        }

        remove_replay_database(&path);
    }

    #[test]
    fn connection_limit_is_enforced_and_released() {
        let active = Arc::new(AtomicUsize::new(0));
        let permits = (0..MAX_CONCURRENT_CONNECTIONS)
            .map(|_| reserve_connection(&active).unwrap())
            .collect::<Vec<_>>();
        assert!(reserve_connection(&active).is_none());
        drop(permits);
        assert_eq!(active.load(Ordering::Acquire), 0);
    }

    #[test]
    fn confirmation_comparison_rejects_changes() {
        assert!(secrets_equal(&[1, 2, 3], &[1, 2, 3]));
        assert!(!secrets_equal(&[1, 2, 3], &[1, 2, 4]));
        assert!(!secrets_equal(&[1, 2, 3], &[1, 2]));
    }
}
