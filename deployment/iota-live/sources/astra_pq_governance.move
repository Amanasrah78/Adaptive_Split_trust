// SPDX-License-Identifier: Apache-2.0

/// Minimal on-chain commitment for ASTRA-PQ governance checkpoints.
///
/// The object contains public commitments only. Authorization policies,
/// authority shares, session identifiers, and session keys never enter it.
module astra_pq_governance::astra_pq_governance;

use iota::event;

const PACKAGE_VERSION: u64 = 1;
const DIGEST_BYTES: u64 = 32;
const MAX_URI_BYTES: u64 = 512;
const MAX_KEY_SET_ID_BYTES: u64 = 128;

const EWrongPackageVersion: u64 = 0;
const EInvalidEpoch: u64 = 1;
const EInvalidPredecessor: u64 = 2;
const EInvalidDigest: u64 = 3;
const EInvalidActivationTime: u64 = 4;
const EInvalidUri: u64 = 5;
const EInvalidKeySetId: u64 = 6;

/// Possession authorizes publication to the shared governance object.
public struct PublisherCap has key, store {
    id: UID,
}

/// Latest governance commitment. The object is shared at package creation.
public struct AstraPQGovernance has key {
    id: UID,
    package_version: u64,
    epoch: u64,
    predecessor_hash: vector<u8>,
    checkpoint_hash: vector<u8>,
    activation_time: u64,
    bundle_uri: vector<u8>,
    governance_key_set_id: vector<u8>,
}

/// Event emitted after a successful monotonic checkpoint update.
public struct EpochPublished has copy, drop {
    governance_object_id: ID,
    package_version: u64,
    epoch: u64,
    predecessor_hash: vector<u8>,
    checkpoint_hash: vector<u8>,
    activation_time: u64,
    bundle_uri: vector<u8>,
    governance_key_set_id: vector<u8>,
}

fun init(ctx: &mut TxContext) {
    let sender = ctx.sender();
    transfer::transfer(PublisherCap { id: object::new(ctx) }, sender);
    transfer::share_object(AstraPQGovernance {
        id: object::new(ctx),
        package_version: PACKAGE_VERSION,
        epoch: 0,
        predecessor_hash: x"0000000000000000000000000000000000000000000000000000000000000000",
        checkpoint_hash: x"0000000000000000000000000000000000000000000000000000000000000000",
        activation_time: 0,
        bundle_uri: b"",
        governance_key_set_id: b"",
    });
}

/// Publishes the next checkpoint commitment.
///
/// Native transaction authorization protects `PublisherCap`. ASTRA-PQ nodes
/// separately verify the detached ML-DSA governance-signature threshold before
/// activating the referenced bundle.
public entry fun publish_epoch(
    _: &PublisherCap,
    governance: &mut AstraPQGovernance,
    package_version: u64,
    next_epoch: u64,
    predecessor_hash: vector<u8>,
    checkpoint_hash: vector<u8>,
    activation_time: u64,
    bundle_uri: vector<u8>,
    governance_key_set_id: vector<u8>,
) {
    assert!(package_version == PACKAGE_VERSION, EWrongPackageVersion);
    assert!(governance.package_version == PACKAGE_VERSION, EWrongPackageVersion);
    assert!(next_epoch == governance.epoch + 1, EInvalidEpoch);
    assert!(predecessor_hash == governance.checkpoint_hash, EInvalidPredecessor);
    assert!(checkpoint_hash.length() == DIGEST_BYTES, EInvalidDigest);
    assert!(activation_time > 0, EInvalidActivationTime);
    assert!(bundle_uri.length() > 0 && bundle_uri.length() <= MAX_URI_BYTES, EInvalidUri);
    assert!(
        governance_key_set_id.length() > 0
            && governance_key_set_id.length() <= MAX_KEY_SET_ID_BYTES,
        EInvalidKeySetId,
    );

    governance.epoch = next_epoch;
    governance.predecessor_hash = predecessor_hash;
    governance.checkpoint_hash = checkpoint_hash;
    governance.activation_time = activation_time;
    governance.bundle_uri = bundle_uri;
    governance.governance_key_set_id = governance_key_set_id;

    event::emit(EpochPublished {
        governance_object_id: object::id(governance),
        package_version,
        epoch: next_epoch,
        predecessor_hash,
        checkpoint_hash,
        activation_time,
        bundle_uri,
        governance_key_set_id,
    });
}

/// Returns the package schema version expected by off-chain synchronizers.
public fun package_version(governance: &AstraPQGovernance): u64 {
    governance.package_version
}

/// Returns the latest published governance epoch.
public fun epoch(governance: &AstraPQGovernance): u64 {
    governance.epoch
}

/// Returns the latest checkpoint commitment.
public fun checkpoint_hash(governance: &AstraPQGovernance): &vector<u8> {
    &governance.checkpoint_hash
}

#[test_only]
fun zero_digest(): vector<u8> {
    x"0000000000000000000000000000000000000000000000000000000000000000"
}

#[test_only]
fun first_digest(): vector<u8> {
    x"1111111111111111111111111111111111111111111111111111111111111111"
}

#[test]
fun publishes_epoch_one_and_preserves_capability() {
    let publisher = @0xA;
    let mut scenario = test_scenario::begin(publisher);
    init(scenario.ctx());

    scenario.next_tx(publisher);
    let cap = scenario.take_from_sender<PublisherCap>();
    let mut governance = scenario.take_shared<AstraPQGovernance>();
    publish_epoch(
        &cap,
        &mut governance,
        PACKAGE_VERSION,
        1,
        zero_digest(),
        first_digest(),
        1_700_000_000,
        b"ipfs://astra-pq/checkpoint-1",
        b"governance-v1",
    );
    assert!(governance.epoch == 1, 100);
    assert!(governance.predecessor_hash == zero_digest(), 101);
    assert!(governance.checkpoint_hash == first_digest(), 102);

    scenario.return_to_sender(cap);
    test_scenario::return_shared(governance);
    scenario.next_tx(publisher);
    let cap_after_publish = scenario.take_from_sender<PublisherCap>();
    scenario.return_to_sender(cap_after_publish);
    scenario.end();
}

#[test]
#[expected_failure(abort_code = EInvalidEpoch, location = Self)]
fun rejects_skipped_epoch() {
    let publisher = @0xA;
    let mut scenario = test_scenario::begin(publisher);
    init(scenario.ctx());

    scenario.next_tx(publisher);
    let cap = scenario.take_from_sender<PublisherCap>();
    let mut governance = scenario.take_shared<AstraPQGovernance>();
    publish_epoch(
        &cap,
        &mut governance,
        PACKAGE_VERSION,
        2,
        zero_digest(),
        first_digest(),
        1_700_000_000,
        b"ipfs://astra-pq/checkpoint-2",
        b"governance-v1",
    );
    abort 200
}

#[test]
#[expected_failure(abort_code = EInvalidPredecessor, location = Self)]
fun rejects_incorrect_predecessor() {
    let publisher = @0xA;
    let mut scenario = test_scenario::begin(publisher);
    init(scenario.ctx());

    scenario.next_tx(publisher);
    let cap = scenario.take_from_sender<PublisherCap>();
    let mut governance = scenario.take_shared<AstraPQGovernance>();
    publish_epoch(
        &cap,
        &mut governance,
        PACKAGE_VERSION,
        1,
        first_digest(),
        first_digest(),
        1_700_000_000,
        b"ipfs://astra-pq/checkpoint-1",
        b"governance-v1",
    );
    abort 201
}

#[test]
#[expected_failure(abort_code = EInvalidDigest, location = Self)]
fun rejects_malformed_checkpoint_digest() {
    let publisher = @0xA;
    let mut scenario = test_scenario::begin(publisher);
    init(scenario.ctx());

    scenario.next_tx(publisher);
    let cap = scenario.take_from_sender<PublisherCap>();
    let mut governance = scenario.take_shared<AstraPQGovernance>();
    publish_epoch(
        &cap,
        &mut governance,
        PACKAGE_VERSION,
        1,
        zero_digest(),
        x"01",
        1_700_000_000,
        b"ipfs://astra-pq/checkpoint-1",
        b"governance-v1",
    );
    abort 202
}
