# ASTRA-PQ live IOTA governance anchor

This directory replaces synthetic ledger observations with a real IOTA Move
shared object. IOTA remains outside the authorization and session critical
paths. Gateways consume only a locally validated checkpoint bundle.

## Security boundary

The Move object provides monotonic publication, ordering, availability, and an
auditable checkpoint commitment. Native IOTA transaction authentication does
not replace ASTRA-PQ governance authentication. Nodes must still validate the
detached ML-DSA governance-signature threshold before activating a bundle.

Never publish credentials, authority shares, session policies, authorization
outputs, KEM material, session identifiers, or traffic metadata.

## Deployment order

1. Install a version-pinned current IOTA CLI and configure a funded testnet
   address. Do not use the archived pre-Rebased `iota-sdk` repository.
2. Run `iota move build` and `iota move test` in this directory.
3. Publish the package with `iota client publish --gas-budget <budget> --json`.
4. Record the package ID, shared `AstraPQGovernance` object ID, and owned
   `PublisherCap` ID from the publication result.
5. Generate epoch 1 only after those IDs are known. The detached ML-DSA
   signature message binds the real network, package, object, package version,
   checkpoint digest, activation time, and governance key-set ID.
6. Call `publish_epoch` with the capability, shared object, epoch fields,
   content-addressed bundle URI, and key-set ID.
7. Observe the updated object through at least two independently administered
   JSON-RPC endpoints.
8. Convert the agreed observation into `LedgerAnchor` and `RpcObservation`
   values, assemble the bundle, call `astra_governance::validate_bundle`, and
   atomically replace the rollback-protected local state.

## Independent observation

The observer uses only Python's standard library and refuses to produce an
artifact unless the required number of distinct endpoint identifiers agree on
all security-relevant Move fields and the IOTA object version and transaction.

```sh
python3 scripts/observe_iota_anchor.py \
  --package-id "$ASTRA_IOTA_PACKAGE_ID" \
  --object-id "$ASTRA_IOTA_GOVERNANCE_OBJECT_ID" \
  --rpc foundation=https://api.testnet.iota.cafe \
  --rpc independent=https://YOUR-INDEPENDENT-RPC.example \
  --required-agreement 2 \
  --output live-iota-observation.json
```

Endpoint labels are evidence metadata, not proof of administrative
independence. The experiment record must identify the actual operators.

The printable IOTA transaction digest is mapped into the existing ASTRA-PQ
`Digest32` field as `SHA3-256(UTF8(previousTransaction))`. The original IOTA
digest is retained in the observation artifact for auditability.

The `publish_epoch` arguments containing hashes, the URI, and the key-set ID
are Move `vector<u8>` values. Supply them through the CLI as byte vectors. Do
not pass a printable hexadecimal digest as its ASCII bytes. Decode the
64-character hexadecimal checkpoint digest into exactly 32 bytes first.

## Fail-closed tests

Before collecting performance measurements, verify that the synchronizer
rejects:

- one agreeing endpoint when the configured quorum is two;
- two endpoints reporting different object versions or checkpoint hashes;
- a package or object ID different from the pinned deployment profile;
- an epoch gap, repeated epoch, or predecessor mismatch;
- an invalid or insufficient detached ML-DSA signature set;
- a checkpoint that is not active or has exceeded its maximum cached age;
- replacement of the local state with a lower IOTA object version.

## Measurements

Record transaction submission, inclusion, multi-endpoint observation, bundle
download, cryptographic validation, and local activation separately. Also
record gas, object version, transaction digest, network checkpoint, endpoint
operator, software revision, and recovery after endpoint isolation. Session
latency must be measured separately to demonstrate that IOTA synchronization
remains off path.
