use anyhow::Context;
use astra_common::Digest32;
use astra_governance::LocalGovernanceState;
use astra_testkit::replay_store::ReplayStore;
use std::env;
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let db = env::args()
        .nth(1)
        .map(PathBuf::from)
        .context("usage: astra-bootstrap-governance-state <replay-db> <scope>")?;

    let scope = env::args()
        .nth(2)
        .context("usage: astra-bootstrap-governance-state <replay-db> <scope>")?;

    anyhow::ensure!(
        scope == "authority:a1"
            || scope == "authority:a2"
            || scope == "authority:a3"
            || scope == "responder",
        "unsupported bootstrap scope: {scope}"
    );

    let checkpoint = [
        0x38, 0x97, 0x28, 0x11, 0x63, 0x40, 0x7b, 0xe8, 0xe7, 0x2a, 0xb9, 0xa3, 0x25, 0xfe, 0xd0,
        0xc0, 0x80, 0x08, 0xb5, 0xf6, 0x33, 0x5b, 0xe6, 0xc3, 0x17, 0x5d, 0xe2, 0x30, 0xa0, 0x8b,
        0x87, 0x3f,
    ];

    let state = LocalGovernanceState {
        highest_epoch: 1,
        checkpoint_hash: Digest32::from_bytes(checkpoint),
        validated_at: 1_788_050_762,
        object_version: 924_792_290,
    };

    let mut store = ReplayStore::open(&db).context("open authority replay database")?;

    if let Some(existing) = store
        .load_governance_state(&scope)
        .context("load existing governance state")?
    {
        anyhow::bail!(
            "refusing bootstrap: governance state already exists for {}: {:?}",
            scope,
            existing
        );
    }

    store
        .store_governance_state(&scope, &state)
        .context("store epoch-1 governance state")?;

    let stored = store
        .load_governance_state(&scope)
        .context("reload stored governance state")?
        .context("bootstrap row disappeared")?;

    anyhow::ensure!(stored == state, "stored state differs from requested state");

    println!(
        "BOOTSTRAP_OK scope={} epoch={} checkpoint={} validated_at={} object_version={}",
        scope,
        stored.highest_epoch,
        stored.checkpoint_hash,
        stored.validated_at,
        stored.object_version
    );

    Ok(())
}
