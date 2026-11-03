#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
observer="${repo_root}/deployment/iota-live/scripts/observe_iota_anchor.py"
finalizer="${ASTRA_IOTA_FINALIZER:-${repo_root}/target/release/astra-iota-governance}"
prepared="${ASTRA_IOTA_PREPARED_CHECKPOINT:-${repo_root}/results/iota-live-checkpoint-epoch1-prepared.json}"
observation="${ASTRA_IOTA_LIVE_OBSERVATION:-${repo_root}/results/iota-live-observation-epoch1.json}"
output="${ASTRA_IOTA_BENCHMARK_OUTPUT:-${repo_root}/results/iota-live-observation-100.jsonl}"
samples="${ASTRA_IOTA_BENCHMARK_SAMPLES:-100}"
pause="${ASTRA_IOTA_BENCHMARK_PAUSE:-0.025}"
fullnode_url="${ASTRA_IOTA_FULLNODE_RPC:-https://api.testnet.iota.cafe}"
indexer_url="${ASTRA_IOTA_INDEXER_RPC:-https://indexer.testnet.iota.cafe}"

: "${ASTRA_IOTA_PACKAGE_ID:?ASTRA_IOTA_PACKAGE_ID is required}"
: "${ASTRA_IOTA_OBJECT_ID:?ASTRA_IOTA_OBJECT_ID is required}"

[[ "$samples" =~ ^[1-9][0-9]*$ ]] || {
    echo "ASTRA_IOTA_BENCHMARK_SAMPLES must be a positive integer" >&2
    exit 2
}

for required in "$observer" "$finalizer" "$prepared" "$observation"; do
    test -e "$required" || {
        echo "required input is missing: $required" >&2
        exit 2
    }
done

test ! -e "$output" || {
    echo "refusing to overwrite $output" >&2
    exit 2
}

tmp_dir="$(mktemp -d)"
cleanup() {
    rm -rf -- "$tmp_dir"
}
trap cleanup EXIT

checkpoint_hash="$(jq -er '.anchor.checkpoint_hash' "$observation")"
object_version="$(jq -er '.anchor.object_version' "$observation")"
previous_transaction="$(jq -er '.anchor.previous_transaction' "$observation")"

: > "$output"

emit_record() {
    local run="$1"
    local profile="$2"
    local elapsed_us="$3"
    local rpc_services="$4"
    local endpoint_order="$5"
    local network_calls="$6"

    jq -cn \
      --argjson run "$run" \
      --arg profile "$profile" \
      --argjson elapsed_us "$elapsed_us" \
      --argjson rpc_services "$rpc_services" \
      --arg endpoint_order "$endpoint_order" \
      --argjson network_calls "$network_calls" \
      --argjson object_version "$object_version" \
      --arg checkpoint_hash "$checkpoint_hash" \
      --arg previous_transaction "$previous_transaction" \
      '{
        schema: "astra-pq-live-iota-latency-v1",
        run: $run,
        profile: $profile,
        success: true,
        elapsed_us: $elapsed_us,
        rpc_services: $rpc_services,
        endpoint_order: $endpoint_order,
        network_calls: $network_calls,
        object_version: $object_version,
        checkpoint_hash: $checkpoint_hash,
        previous_transaction: $previous_transaction,
        session_critical_path: false,
        administratively_independent: false
      }' >> "$output"
}

run_observer() {
    local run="$1"
    local profile="$2"
    local output_json="${tmp_dir}/${run}-${profile}.json"
    local stderr_file="${tmp_dir}/${run}-${profile}.stderr"
    local start_ns end_ns elapsed_us endpoint_order rpc_services network_calls
    local -a rpc_args

    case "$profile" in
        fullnode-observation)
            rpc_args=(
                --rpc "iota-foundation-fullnode=${fullnode_url}"
                --required-agreement 1
            )
            endpoint_order="fullnode"
            rpc_services=1
            network_calls=2
            ;;
        indexer-observation)
            rpc_args=(
                --rpc "iota-foundation-indexer=${indexer_url}"
                --required-agreement 1
            )
            endpoint_order="indexer"
            rpc_services=1
            network_calls=2
            ;;
        two-service-agreement)
            if (( run % 2 == 1 )); then
                rpc_args=(
                    --rpc "iota-foundation-fullnode=${fullnode_url}"
                    --rpc "iota-foundation-indexer=${indexer_url}"
                    --required-agreement 2
                )
                endpoint_order="fullnode,indexer"
            else
                rpc_args=(
                    --rpc "iota-foundation-indexer=${indexer_url}"
                    --rpc "iota-foundation-fullnode=${fullnode_url}"
                    --required-agreement 2
                )
                endpoint_order="indexer,fullnode"
            fi
            rpc_services=2
            network_calls=4
            ;;
        *)
            echo "unknown observer profile: $profile" >&2
            exit 2
            ;;
    esac

    start_ns="$(date +%s%N)"
    if ! python3 "$observer" \
        --package-id "$ASTRA_IOTA_PACKAGE_ID" \
        --object-id "$ASTRA_IOTA_OBJECT_ID" \
        "${rpc_args[@]}" \
        --output "$output_json" \
        >/dev/null 2>"$stderr_file"; then
        echo "observer failed for run=$run profile=$profile" >&2
        sed -n '1,120p' "$stderr_file" >&2
        exit 1
    fi
    end_ns="$(date +%s%N)"
    elapsed_us=$(( (end_ns - start_ns) / 1000 ))

    jq -e \
      --arg checkpoint_hash "$checkpoint_hash" \
      --argjson object_version "$object_version" \
      '.live_iota_claim == true and
       .anchor.checkpoint_hash == $checkpoint_hash and
       .anchor.object_version == $object_version' \
      "$output_json" >/dev/null

    emit_record \
        "$run" "$profile" "$elapsed_us" \
        "$rpc_services" "$endpoint_order" "$network_calls"
}

run_finalizer() {
    local run="$1"
    local bundle="${tmp_dir}/${run}-bundle.json"
    local state="${tmp_dir}/${run}-state.json"
    local stderr_file="${tmp_dir}/${run}-finalization.stderr"
    local stdout_file="${tmp_dir}/${run}-finalization.stdout.json"
    local start_ns end_ns elapsed_us

    start_ns="$(date +%s%N)"
    if ! env \
        ASTRA_IOTA_PREPARED_CHECKPOINT="$prepared" \
        ASTRA_IOTA_LIVE_OBSERVATION="$observation" \
        ASTRA_IOTA_BUNDLE_OUTPUT="$bundle" \
        ASTRA_IOTA_STATE_OUTPUT="$state" \
        "$finalizer" finalize \
        >"$stdout_file" 2>"$stderr_file"; then
        echo "finalizer failed for run=$run" >&2
        sed -n '1,120p' "$stderr_file" >&2
        exit 1
    fi
    end_ns="$(date +%s%N)"
    elapsed_us=$(( (end_ns - start_ns) / 1000 ))

    jq -e \
      --arg checkpoint_hash "$checkpoint_hash" \
      '.checkpoint_hash == $checkpoint_hash' \
      "$stdout_file" >/dev/null

    emit_record \
        "$run" "local-finalization" "$elapsed_us" \
        0 "local" 0
}

profiles=(
    fullnode-observation
    indexer-observation
    two-service-agreement
    local-finalization
)

for ((run = 1; run <= samples; run++)); do
    rotation=$(( (run - 1) % ${#profiles[@]} ))
    for ((offset = 0; offset < ${#profiles[@]}; offset++)); do
        index=$(( (rotation + offset) % ${#profiles[@]} ))
        profile="${profiles[$index]}"
        case "$profile" in
            local-finalization)
                run_finalizer "$run"
                ;;
            *)
                run_observer "$run" "$profile"
                ;;
        esac
        sleep "$pause"
    done
done

jq -e -s \
  --argjson samples "$samples" \
  'length == ($samples * 4) and all(.success == true)' \
  "$output" >/dev/null

echo "live_iota_benchmark_complete=true"
echo "samples_per_profile=$samples"
echo "total_records=$((samples * 4))"
echo "output=$output"
