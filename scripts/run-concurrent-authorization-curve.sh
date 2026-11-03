#!/usr/bin/env bash
set -euo pipefail

root=/home/astraadmin/astra-pq
client="${root}/bin/astra-distributed-client"
result="${ASTRA_CONCURRENCY_RESULT:-${root}/results/concurrent-authorization-curve.jsonl}"
levels_result="${ASTRA_CONCURRENCY_LEVELS_RESULT:-${root}/results/concurrent-authorization-curve-levels.jsonl}"
stderr_result="${ASTRA_CONCURRENCY_STDERR_RESULT:-${root}/results/concurrent-authorization-curve-stderr.txt}"
target_samples="${ASTRA_CONCURRENCY_TARGET_SAMPLES:-1000}"
cooldown_seconds="${ASTRA_CONCURRENCY_COOLDOWN_SECONDS:-2}"
levels=(1 32 2 24 4 16 8)

for output in "${result}" "${levels_result}" "${stderr_result}"; do
  if [[ -e "${output}" ]]; then
    echo "refusing to overwrite existing output: ${output}" >&2
    exit 1
  fi
done

mkdir -p "$(dirname "${result}")"
work_root="$(mktemp -d "$(dirname "${result}")/.concurrency-curve.XXXXXX")"
raw_temporary="${work_root}/combined.jsonl"
levels_temporary="${work_root}/levels.jsonl"
stderr_temporary="${work_root}/stderr.txt"
touch "${raw_temporary}" "${levels_temporary}" "${stderr_temporary}"
chmod 600 "${raw_temporary}" "${levels_temporary}" "${stderr_temporary}"

cleanup() {
  if [[ "${work_root}" == "$(dirname "${result}")"/.concurrency-curve.* ]]; then
    rm -rf -- "${work_root}"
  fi
}
trap cleanup EXIT

common_environment=(
  "ASTRA_THRESHOLD=3"
  "ASTRA_GATEWAY_ID=gateway-a"
  "ASTRA_GOVERNANCE_BUNDLE=${root}/config/governance/governance-bundle.json"
  "ASTRA_GATEWAY_SIGNING_KEY=${root}/secrets/gateway-request/request-signing.sk"
  "ASTRA_GATEWAY_PUBLIC_KEY=${root}/secrets/gateway-request/request-signing.pk"
  "ASTRA_AUTHORITY_PUBLIC_KEY_ROOT=${root}/config/authority-public-keys"
  "ASTRA_AUTHORITY_ENDPOINTS=a1=172.16.64.11:7443,a2=172.16.64.12:7443,a3=172.16.64.13:7443,a4=172.16.64.14:7443,a5=172.16.64.15:7443,a6=172.16.64.16:7443,a7=172.16.64.17:7443"
  "ASTRA_BENCHMARK_BARRIER_TIMEOUT_SECONDS=60"
)

expected_total=0
sequence=0
for concurrency in "${levels[@]}"; do
  sequence=$((sequence + 1))
  repetitions=$(((target_samples + concurrency - 1) / concurrency))
  expected_records=$((concurrency * repetitions))
  expected_total=$((expected_total + expected_records))
  level_dir="${work_root}/level-${concurrency}"
  start_file="${level_dir}/start"
  mkdir -p "${level_dir}"

  pids=()
  for ((worker = 1; worker <= concurrency; worker++)); do
    ready_file="${level_dir}/ready-${worker}"
    worker_output="${level_dir}/worker-${worker}.jsonl"
    worker_stderr="${level_dir}/worker-${worker}.stderr"
    env \
      "${common_environment[@]}" \
      "ASTRA_REPETITIONS=${repetitions}" \
      "ASTRA_BENCHMARK_READY_FILE=${ready_file}" \
      "ASTRA_BENCHMARK_START_FILE=${start_file}" \
      "${client}" \
      > "${worker_output}" \
      2> "${worker_stderr}" &
    pids+=("$!")
  done

  readiness_deadline=$((SECONDS + 60))
  while true; do
    ready_count="$(find "${level_dir}" -maxdepth 1 -type f -name 'ready-*' | wc -l)"
    if ((ready_count == concurrency)); then
      break
    fi
    if ((SECONDS >= readiness_deadline)); then
      echo "timed out waiting for concurrency ${concurrency}: ${ready_count}/${concurrency} ready" >&2
      exit 1
    fi
    sleep 0.02
  done

  start_ns="$(date +%s%N)"
  touch "${start_file}"
  successful_workers=0
  for pid in "${pids[@]}"; do
    if wait "${pid}"; then
      successful_workers=$((successful_workers + 1))
    fi
  done
  end_ns="$(date +%s%N)"
  elapsed_us=$(((end_ns - start_ns) / 1000))

  observed_records=0
  for ((worker = 1; worker <= concurrency; worker++)); do
    worker_output="${level_dir}/worker-${worker}.jsonl"
    worker_stderr="${level_dir}/worker-${worker}.stderr"
    worker_records="$(wc -l < "${worker_output}")"
    observed_records=$((observed_records + worker_records))
    if [[ -s "${worker_stderr}" ]]; then
      {
        printf 'concurrency=%s worker=%s\n' "${concurrency}" "${worker}"
        cat "${worker_stderr}"
      } >> "${stderr_temporary}"
    fi
    jq -c \
      --argjson concurrency_level "${concurrency}" \
      --argjson worker_id "${worker}" \
      --argjson level_sequence "${sequence}" \
      '. + {
        concurrency_level: $concurrency_level,
        worker_id: $worker_id,
        concurrency_level_sequence: $level_sequence
      }' \
      "${worker_output}" >> "${raw_temporary}"
  done

  jq -n -c \
    --argjson concurrency_level "${concurrency}" \
    --argjson level_sequence "${sequence}" \
    --argjson workers_started "${concurrency}" \
    --argjson workers_ready "${ready_count}" \
    --argjson workers_successful "${successful_workers}" \
    --argjson repetitions_per_worker "${repetitions}" \
    --argjson expected_records "${expected_records}" \
    --argjson observed_records "${observed_records}" \
    --argjson elapsed_us "${elapsed_us}" \
    '{
      schema: "astra-pq-concurrent-authorization-level-v1",
      concurrency_level: $concurrency_level,
      level_sequence: $level_sequence,
      workers_started: $workers_started,
      workers_ready: $workers_ready,
      workers_successful: $workers_successful,
      repetitions_per_worker: $repetitions_per_worker,
      expected_records: $expected_records,
      observed_records: $observed_records,
      elapsed_us: $elapsed_us,
      throughput_authorizations_per_second:
        (($observed_records * 1000000000 / $elapsed_us | round) / 1000),
      all_workers_successful: ($workers_successful == $workers_started)
    }' >> "${levels_temporary}"

  anyhow_failure=0
  if ((successful_workers != concurrency || observed_records != expected_records)); then
    anyhow_failure=1
  fi
  if ((anyhow_failure != 0)); then
    echo "concurrency ${concurrency} did not complete successfully" >&2
    exit 1
  fi
  sleep "${cooldown_seconds}"
done

jq -e -s \
  --argjson expected_total "${expected_total}" \
  '
    length == $expected_total
    and all(.success == true)
    and all(.threshold == 3)
    and all(.selected_coalition == ["a1", "a2", "a3"])
    and all(.coordinated_start_barrier == true)
    and all(.connection_mode == "persistent-preconnected-excluded-from-timing")
  ' "${raw_temporary}" >/dev/null

jq -e -s '
  length == 7
  and all(.all_workers_successful == true)
  and all(.workers_started == .workers_ready)
  and all(.expected_records == .observed_records)
' "${levels_temporary}" >/dev/null

mv "${raw_temporary}" "${result}"
mv "${levels_temporary}" "${levels_result}"
mv "${stderr_temporary}" "${stderr_result}"
trap - EXIT
cleanup

sha256sum "${result}" "${levels_result}" "${stderr_result}"
