//! Gateway A client for the distributed ASTRA-PQ dual-gate handshake.
//!
//! The client obtains every canonical R3 authorization clause from the three
//! lab authorities, verifies and combines the six signed partials locally,
//! encapsulates ML-KEM-768 to Gateway B, and completes explicit bidirectional
//! key confirmation without exporting the derived session key.

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
use astra_dprf::{DprfBackend, EvaluationRequest, lwr::LwrExactCoalitionBackend};
use astra_gateway::{AuthorityVerificationKeys, SessionEstablishmentRequest, establish_session};
use astra_governance::{
    GovernanceBundle, LocalGovernanceState, checkpoint_is_fresh, validate_bundle,
};
use astra_pqcrypto::{ConfirmationRole, PqProvider, derive_session_confirmation_tag};
use astra_testkit::session_wire::{
    MAX_GATEWAY_MESSAGE_BYTES, SESSION_COMPLETION_SCHEMA, SESSION_FINISH_SCHEMA,
    SESSION_REQUEST_SCHEMA, SessionHandshakeFinish, SessionHandshakeRequest,
    SignedSessionHandshakeCompletion, SignedSessionHandshakeResponse, request_transcript_hash,
    sign_session_finish, sign_session_request, verify_session_completion, verify_session_response,
};
use astra_testkit::{SESSION_EPOCH, SESSION_SHARE_VERSION, r3_lab_synthesis};
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

const AUTHORITY_WIRE_SCHEMA: &str = "astra-pq-authority-wire-v1";
const REPORT_SCHEMA: &str = "astra-pq-distributed-session-v1";
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const INITIATOR_ID: &str = "gateway-a";
const RESPONDER_ID: &str = "gateway-b";
const SESSION_ID_LABEL: &[u8] = b"ASTRA-PQ-v1/distributed-session-id";
const PREHANDSHAKE_LABEL: &[u8] = b"ASTRA-PQ-v1/distributed-prehandshake";
const SIGNING_SELF_TEST_MESSAGE: &[u8] = b"ASTRA-PQ initiator signing-key self-test v1";

#[derive(Debug, Serialize, Deserialize)]
struct AuthorityWireResponse {
    schema: String,
    authority_id: String,
    success: bool,
    evidence: Option<SignedPartialEvidence>,
    error: Option<String>,
    processing_us: u128,
}

struct AuthorityConnection {
    authority_id: String,
    stream: TcpStream,
}

struct NetworkEvidence {
    evidence: SignedPartialEvidence,
    round_trip_us: u128,
    processing_us: u128,
    response_bytes: usize,
}

fn main() -> anyhow::Result<()> {
    let repetitions = required_usize("ASTRA_SESSION_REPETITIONS")?;
    anyhow::ensure!(repetitions >= 1, "session repetitions must be positive");
    let governance_path = required_path("ASTRA_GOVERNANCE_BUNDLE")?;
    let initiator_secret_path = required_path("ASTRA_INITIATOR_SIGNING_KEY")?;
    let initiator_public_path = required_path("ASTRA_INITIATOR_SIGNING_PUBLIC_KEY")?;
    let responder_public_path = required_path("ASTRA_RESPONDER_SIGNING_PUBLIC_KEY")?;
    let responder_kem_public_path = required_path("ASTRA_RESPONDER_KEM_PUBLIC")?;
    let authority_key_root = required_path("ASTRA_AUTHORITY_PUBLIC_KEY_ROOT")?;
    let authority_endpoints = parse_endpoints(&required_environment("ASTRA_AUTHORITY_ENDPOINTS")?)?;
    let responder_endpoint = required_environment("ASTRA_SESSION_RESPONDER_ENDPOINT")?
        .parse::<SocketAddr>()
        .context("parse session responder endpoint")?;
    for required in ["a1", "a2", "a3"] {
        anyhow::ensure!(
            authority_endpoints.contains_key(required),
            "missing endpoint for required R3 authority {required}"
        );
    }

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
        governance_bundle.checkpoint.epoch == SESSION_EPOCH,
        "governance epoch differs from the session-share epoch"
    );
    let checkpoint = governance_state.checkpoint_hash;

    let initiator_signing_key = provider.import_signature_secret_key(
        fs::read(&initiator_secret_path)
            .with_context(|| format!("read {}", initiator_secret_path.display()))?,
    )?;
    let initiator_signing_public = fs::read(&initiator_public_path)
        .with_context(|| format!("read {}", initiator_public_path.display()))?;
    let signing_self_test = provider
        .sign(&initiator_signing_key, SIGNING_SELF_TEST_MESSAGE)
        .context("initiator signing-key self-test")?;
    provider
        .verify(
            &initiator_signing_public,
            SIGNING_SELF_TEST_MESSAGE,
            &signing_self_test,
        )
        .context("initiator signing public/private key mismatch")?;
    let responder_signing_public = fs::read(&responder_public_path)
        .with_context(|| format!("read {}", responder_public_path.display()))?;
    let responder_kem_public = fs::read(&responder_kem_public_path)
        .with_context(|| format!("read {}", responder_kem_public_path.display()))?;
    let authority_verification_keys = ["a1", "a2", "a3"]
        .into_iter()
        .map(|authority| {
            let path = authority_key_root.join(format!("{authority}.pk"));
            let key = fs::read(&path)
                .with_context(|| format!("read authority key {}", path.display()))?;
            Ok((authority.to_owned(), key))
        })
        .collect::<anyhow::Result<AuthorityVerificationKeys>>()?;

    let mut connections = BTreeMap::new();
    for authority in ["a1", "a2", "a3"] {
        let endpoint = authority_endpoints[authority];
        let connection = connect_authority(authority, endpoint)?;
        connections.insert(authority.to_owned(), connection);
    }
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

        let kem_start = Instant::now();
        let encapsulation = provider
            .encapsulate(&responder_kem_public)
            .context("encapsulate to Gateway B")?;
        let kem_encapsulation_us = kem_start.elapsed().as_micros();
        let context = experiment_context(run, checkpoint, encapsulation.ciphertext());

        let synthesis_start = Instant::now();
        let synthesis = r3_lab_synthesis(&context).context("synthesize canonical R3 policy")?;
        let synthesis_us = synthesis_start.elapsed().as_micros();
        let input = authorization_input(&context, &synthesis.policy_hash)?;

        let signing_start = Instant::now();
        let request_plan = build_authority_request_plan(
            &provider,
            &initiator_signing_key,
            &context,
            &synthesis,
            input,
        )?;
        let authority_request_signing_us = signing_start.elapsed().as_micros();
        let authority_request_bytes_total = request_plan
            .values()
            .flat_map(|requests| requests.iter())
            .map(Vec::len)
            .sum::<usize>();

        let collection_start = Instant::now();
        let network_batches = thread::scope(|scope| {
            let handles = connections
                .iter_mut()
                .map(|(authority, connection)| {
                    let requests = request_plan
                        .get(authority)
                        .expect("request plan covers every required authority");
                    scope.spawn(move || {
                        requests
                            .iter()
                            .map(|request| request_evidence(connection, request))
                            .collect::<anyhow::Result<Vec<_>>>()
                    })
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
        let authority_collection_us = collection_start.elapsed().as_micros();
        let network_results = network_batches.into_iter().flatten().collect::<Vec<_>>();
        anyhow::ensure!(
            network_results.len() == 6,
            "canonical R3 collection did not return six evidence items"
        );

        let verification_start = Instant::now();
        for result in &network_results {
            let authority = &result.evidence.partial.authority_id;
            let verification_key = authority_verification_keys
                .get(authority)
                .context("evidence came from an unknown authority")?;
            verify_evidence(&provider, verification_key, &context, &result.evidence)
                .with_context(|| format!("verify evidence from {authority}"))?;
            anyhow::ensure!(
                result.evidence.policy_hash == synthesis.policy_hash,
                "authority evidence policy hash mismatch"
            );
        }
        let evidence_verification_us = verification_start.elapsed().as_micros();
        let evidence = network_results
            .iter()
            .map(|result| result.evidence.clone())
            .collect::<Vec<_>>();

        let session_request = SessionHandshakeRequest {
            schema: SESSION_REQUEST_SCHEMA.to_owned(),
            initiator_gateway: INITIATOR_ID.to_owned(),
            responder_gateway: RESPONDER_ID.to_owned(),
            context: context.clone(),
            synthesis: synthesis.clone(),
            share_version: SESSION_SHARE_VERSION,
            kem_ciphertext: encapsulation.ciphertext().to_vec(),
            evidence,
        };
        let signed_session_request =
            sign_session_request(&provider, &initiator_signing_key, session_request)?;
        let transcript = astra_testkit::session_wire::authenticated_request_transcript(
            &signed_session_request.request,
        )?;
        let transcript_hash = request_transcript_hash(&transcript);

        let local_establishment_start = Instant::now();
        let established = establish_session(
            &provider,
            &backend,
            SessionEstablishmentRequest {
                context: &signed_session_request.request.context,
                synthesis: &signed_session_request.request.synthesis,
                share_version: signed_session_request.request.share_version,
                verification_keys: &authority_verification_keys,
                evidence: &signed_session_request.request.evidence,
                kem_secret: encapsulation.shared_secret(),
                authenticated_transcript: &transcript,
                governance_state: &governance_state,
                governance_checkpoint: &governance_bundle.checkpoint,
                now: unix_time()?,
            },
        )?;
        let local_session_establishment_us = local_establishment_start.elapsed().as_micros();
        let expected_responder_confirmation = derive_session_confirmation_tag(
            &established.session_key,
            &transcript,
            ConfirmationRole::Responder,
        )?;
        let initiator_confirmation = derive_session_confirmation_tag(
            &established.session_key,
            &transcript,
            ConfirmationRole::Initiator,
        )?;

        let responder_start = Instant::now();
        let mut responder_stream = TcpStream::connect_timeout(&responder_endpoint, CONNECT_TIMEOUT)
            .with_context(|| format!("connect to session responder at {responder_endpoint}"))?;
        configure_stream(&responder_stream)?;
        let session_request_bytes =
            write_json_frame(&mut responder_stream, &signed_session_request)?;
        let signed_response: SignedSessionHandshakeResponse =
            read_json_frame(&mut responder_stream)?;
        verify_session_response(&provider, &responder_signing_public, &signed_response)?;
        anyhow::ensure!(
            signed_response.response.session_id == context.session_id
                && signed_response.response.request_transcript_hash == transcript_hash
                && signed_response.response.authorization_input == established.authorization_input
                && signed_response.response.contributors == established.contributors,
            "responder result differs from local session establishment"
        );
        anyhow::ensure!(
            digests_equal(
                &signed_response.response.responder_confirmation,
                &expected_responder_confirmation
            ),
            "responder key confirmation failed"
        );

        let finish = sign_session_finish(
            &provider,
            &initiator_signing_key,
            SessionHandshakeFinish {
                schema: SESSION_FINISH_SCHEMA.to_owned(),
                session_id: context.session_id,
                request_transcript_hash: transcript_hash,
                initiator_confirmation,
            },
        )?;
        let finish_bytes = write_json_frame(&mut responder_stream, &finish)?;
        let completion: SignedSessionHandshakeCompletion = read_json_frame(&mut responder_stream)?;
        verify_session_completion(&provider, &responder_signing_public, &completion)?;
        anyhow::ensure!(
            completion.completion.schema == SESSION_COMPLETION_SCHEMA
                && completion.completion.session_id == context.session_id
                && completion.completion.request_transcript_hash == transcript_hash
                && completion.completion.accepted,
            "responder completion binding mismatch"
        );
        let responder_handshake_us = responder_start.elapsed().as_micros();

        let authority_response_bytes_total = network_results
            .iter()
            .map(|result| result.response_bytes)
            .sum::<usize>();
        let authority_round_trip_us = network_results
            .iter()
            .map(|result| result.round_trip_us)
            .collect::<Vec<_>>();
        let authority_processing_us = network_results
            .iter()
            .map(|result| result.processing_us)
            .collect::<Vec<_>>();
        println!(
            "{}",
            json!({
                "schema": REPORT_SCHEMA,
                "success": true,
                "run": run,
                "session_id": context.session_id.to_string(),
                "risk_class": "R3",
                "clause_count": synthesis.structure.clauses.len(),
                "evidence_count": signed_session_request.request.evidence.len(),
                "contributors": established.contributors,
                "kem": provider.metadata().kem_algorithm,
                "signature": provider.metadata().signature_algorithm,
                "dprf_backend": backend.backend_id(),
                "security_profile": LwrExactCoalitionBackend::security_profile(),
                "malicious_robust": false,
                "proactive_refresh_implemented": false,
                "governance_validation": "off-path-signed-bundle-synthetic-iota-observations",
                "live_iota_claim": false,
                "transport": "bounded-json-over-tcp-isolated-lab-no-confidentiality",
                "session_key_exported": false,
                "bidirectional_key_confirmation": true,
                "authority_request_bytes_total": authority_request_bytes_total,
                "authority_response_bytes_total": authority_response_bytes_total,
                "gateway_session_request_bytes": session_request_bytes,
                "gateway_finish_bytes": finish_bytes,
                "authority_round_trip_us": authority_round_trip_us,
                "authority_processing_us": authority_processing_us,
                "timing_us": {
                    "kem_encapsulation": kem_encapsulation_us,
                    "policy_synthesis": synthesis_us,
                    "authority_request_signing": authority_request_signing_us,
                    "authority_collection": authority_collection_us,
                    "evidence_verification": evidence_verification_us,
                    "initiator_session_establishment": local_session_establishment_us,
                    "responder_handshake": responder_handshake_us,
                    "total": total_start.elapsed().as_micros()
                }
            })
        );
    }
    Ok(())
}

fn build_authority_request_plan(
    provider: &PqProvider,
    signing_key: &astra_pqcrypto::SecretBytes,
    context: &SessionContext,
    synthesis: &astra_synthesizer::SynthesisResult,
    input: Digest32,
) -> anyhow::Result<BTreeMap<String, Vec<Vec<u8>>>> {
    let mut plan = BTreeMap::<String, Vec<Vec<u8>>>::new();
    for clause in &synthesis.structure.clauses {
        anyhow::ensure!(
            clause.members.len() == usize::from(clause.threshold),
            "session LWR profile requires exact clause coalitions"
        );
        for member in &clause.members {
            let request = AuthorityRequest {
                context: context.clone(),
                policy_hash: synthesis.policy_hash,
                evaluation: EvaluationRequest {
                    clause_id: clause.id.clone(),
                    epoch: context.epoch,
                    share_version: SESSION_SHARE_VERSION,
                    input,
                },
            };
            let signed = sign_authority_request(provider, INITIATOR_ID, signing_key, request)?;
            plan.entry(member.authority_id.clone())
                .or_default()
                .push(serde_json::to_vec(&signed)?);
        }
    }
    anyhow::ensure!(
        plan.keys().map(String::as_str).eq(["a1", "a2", "a3"]),
        "canonical R3 request plan has unexpected authorities"
    );
    anyhow::ensure!(
        plan.values().map(Vec::len).sum::<usize>() == 6,
        "canonical R3 request plan must contain six evaluations"
    );
    Ok(plan)
}

fn connect_authority(
    authority_id: &str,
    endpoint: SocketAddr,
) -> anyhow::Result<AuthorityConnection> {
    let stream = TcpStream::connect_timeout(&endpoint, CONNECT_TIMEOUT)
        .with_context(|| format!("connect to authority {authority_id} at {endpoint}"))?;
    configure_stream(&stream)?;
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
    write_raw_frame(&mut connection.stream, encoded_request)?;
    let encoded_response = read_raw_frame(&mut connection.stream)?;
    let round_trip_us = start.elapsed().as_micros();
    let response: AuthorityWireResponse = serde_json::from_slice(&encoded_response)
        .with_context(|| format!("decode response from {}", connection.authority_id))?;
    anyhow::ensure!(
        response.schema == AUTHORITY_WIRE_SCHEMA,
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
        .context("successful authority response lacks evidence")?;
    Ok(NetworkEvidence {
        evidence,
        round_trip_us,
        processing_us: response.processing_us,
        response_bytes: encoded_response.len(),
    })
}

fn experiment_context(run: usize, checkpoint: Digest32, ciphertext: &[u8]) -> SessionContext {
    let run_bytes = (run as u64).to_be_bytes();
    let session_digest = hash_domain_separated(SESSION_ID_LABEL, &[ciphertext, &run_bytes]);
    let prehandshake_hash = hash_domain_separated(
        PREHANDSHAKE_LABEL,
        &[ciphertext, checkpoint.as_bytes(), &run_bytes],
    );
    SessionContext {
        protocol_version: PROTOCOL_VERSION,
        session_id: SessionId::from_bytes(*session_digest.as_bytes()),
        epoch: SESSION_EPOCH,
        source_domain: "domain-a".to_owned(),
        destination_domain: "domain-b".to_owned(),
        subject: "synthetic-operator:17".to_owned(),
        resource: "synthetic-plc:4".to_owned(),
        action: "synthetic-safety-actuation".to_owned(),
        risk: RiskClass::R3,
        gateway_transcript_hash: prehandshake_hash,
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

fn configure_stream(stream: &TcpStream) -> anyhow::Result<()> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    Ok(())
}

fn read_raw_frame(stream: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
    let mut length_bytes = [0_u8; 4];
    stream.read_exact(&mut length_bytes)?;
    let length = usize::try_from(u32::from_be_bytes(length_bytes))
        .context("frame length does not fit this platform")?;
    anyhow::ensure!(
        (1..=MAX_GATEWAY_MESSAGE_BYTES).contains(&length),
        "invalid frame length"
    );
    let mut encoded = vec![0_u8; length];
    stream.read_exact(&mut encoded)?;
    Ok(encoded)
}

fn write_raw_frame(stream: &mut TcpStream, encoded: &[u8]) -> anyhow::Result<usize> {
    anyhow::ensure!(
        (1..=MAX_GATEWAY_MESSAGE_BYTES).contains(&encoded.len()),
        "invalid frame length"
    );
    let length = u32::try_from(encoded.len()).context("frame is too large")?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(encoded)?;
    stream.flush()?;
    Ok(encoded.len() + 4)
}

fn read_json_frame<T: serde::de::DeserializeOwned>(stream: &mut TcpStream) -> anyhow::Result<T> {
    serde_json::from_slice(&read_raw_frame(stream)?).context("decode gateway frame")
}

fn write_json_frame<T: Serialize>(stream: &mut TcpStream, value: &T) -> anyhow::Result<usize> {
    let encoded = serde_json::to_vec(value).context("encode gateway frame")?;
    write_raw_frame(stream, &encoded)
}

fn required_environment(name: &str) -> anyhow::Result<String> {
    let value = env::var(name).with_context(|| format!("missing {name}"))?;
    anyhow::ensure!(!value.trim().is_empty(), "{name} is empty");
    Ok(value)
}

fn required_path(name: &str) -> anyhow::Result<PathBuf> {
    Ok(PathBuf::from(required_environment(name)?))
}

fn required_usize(name: &str) -> anyhow::Result<usize> {
    required_environment(name)?
        .parse::<usize>()
        .with_context(|| format!("parse {name} as a positive integer"))
}

fn unix_time() -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock precedes Unix epoch")?
        .as_secs())
}

fn digests_equal(left: &Digest32, right: &Digest32) -> bool {
    left.as_bytes()
        .iter()
        .zip(right.as_bytes())
        .fold(0_u8, |difference, (left_byte, right_byte)| {
            difference | (*left_byte ^ *right_byte)
        })
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_endpoint_identifier_is_rejected() {
        assert!(parse_endpoints("a1=127.0.0.1:1,a1=127.0.0.1:2").is_err());
    }

    #[test]
    fn session_context_is_r3_and_ciphertext_bound() {
        let checkpoint = Digest32::from_bytes([7; 32]);
        let first = experiment_context(1, checkpoint, &[1; 32]);
        let repeated = experiment_context(1, checkpoint, &[1; 32]);
        let changed = experiment_context(1, checkpoint, &[2; 32]);
        assert_eq!(first, repeated);
        assert_ne!(first.session_id, changed.session_id);
        assert_ne!(
            first.gateway_transcript_hash,
            changed.gateway_transcript_hash
        );
        assert_eq!(first.risk, RiskClass::R3);
    }
}
