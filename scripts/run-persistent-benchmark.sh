#!/usr/bin/env bash
set -euo pipefail
umask 077

client=/home/astraadmin/astra-pq/bin/astra-distributed-client
result=/home/astraadmin/astra-pq/results/distributed-persistent-randomized-100.jsonl
temporary_file=""

cleanup() {
  if [[ -n "${temporary_file}" && -f "${temporary_file}" ]]; then
    rm -f "${temporary_file}"
  fi
}
trap cleanup EXIT

mkdir -p /home/astraadmin/astra-pq/results
: > "${result}"

export ASTRA_GATEWAY_ID=gateway-a
export ASTRA_GOVERNANCE_BUNDLE=/home/astraadmin/astra-pq/config/governance/governance-bundle.json
export ASTRA_GATEWAY_SIGNING_KEY=/home/astraadmin/astra-pq/secrets/gateway-request/request-signing.sk
export ASTRA_GATEWAY_PUBLIC_KEY=/home/astraadmin/astra-pq/secrets/gateway-request/request-signing.pk
export ASTRA_AUTHORITY_PUBLIC_KEY_ROOT=/home/astraadmin/astra-pq/config/authority-public-keys
export ASTRA_AUTHORITY_ENDPOINTS=a1=172.16.64.11:7443,a2=172.16.64.12:7443,a3=172.16.64.13:7443,a4=172.16.64.14:7443,a5=172.16.64.15:7443,a6=172.16.64.16:7443,a7=172.16.64.17:7443

for batch in 1 2 3 4 5; do
  mapfile -t threshold_order < <(
    printf '%s\n' 1 2 3 4 5 6 7 | shuf
  )

  for threshold in "${threshold_order[@]}"; do
    temporary_file="$(mktemp)"

    ASTRA_THRESHOLD="${threshold}" \
    ASTRA_REPETITIONS=22 \
      "${client}" > "${temporary_file}"

    # Discard two warm-up requests, retaining 20 measured runs.
    tail -n +3 "${temporary_file}" >> "${result}"
    rm -f "${temporary_file}"
    temporary_file=""
  done
done

jq -e -s '
  length == 700
  and all(.[]; .success == true)
  and ([group_by(.threshold)[] | length] | all(. == 100))
  and (
    [.[].connection_mode] | unique
    == ["persistent-preconnected-excluded-from-timing"]
  )
' "${result}"

sha256sum "${result}"
