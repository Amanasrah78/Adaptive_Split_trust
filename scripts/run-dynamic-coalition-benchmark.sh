#!/usr/bin/env bash
set -euo pipefail
umask 077

client=/home/astraadmin/astra-pq/bin/astra-distributed-client
result=/home/astraadmin/astra-pq/results/dynamic-coalition-controlled-exclusion-100.jsonl

mkdir -p /home/astraadmin/astra-pq/results
: > "${result}"

export ASTRA_THRESHOLD=3
export ASTRA_REPETITIONS=1
export ASTRA_GATEWAY_ID=gateway-a
export ASTRA_GOVERNANCE_BUNDLE=/home/astraadmin/astra-pq/config/governance/governance-bundle.json
export ASTRA_GATEWAY_SIGNING_KEY=/home/astraadmin/astra-pq/secrets/gateway-request/request-signing.sk
export ASTRA_GATEWAY_PUBLIC_KEY=/home/astraadmin/astra-pq/secrets/gateway-request/request-signing.pk
export ASTRA_AUTHORITY_PUBLIC_KEY_ROOT=/home/astraadmin/astra-pq/config/authority-public-keys
export ASTRA_AUTHORITY_ENDPOINTS=a1=172.16.64.11:7443,a2=172.16.64.12:7443,a3=172.16.64.13:7443,a4=172.16.64.14:7443,a5=172.16.64.15:7443,a6=172.16.64.16:7443,a7=172.16.64.17:7443

excluded_for_count() {
  case "$1" in
    0) printf '%s' '' ;;
    1) printf '%s' 'a1' ;;
    2) printf '%s' 'a1,a2' ;;
    3) printf '%s' 'a1,a2,a3' ;;
    4) printf '%s' 'a1,a2,a3,a4' ;;
    *) return 1 ;;
  esac
}

for batch in 1 2 3 4 5; do
  mapfile -t scenario_order < <(
    printf '%s\n' 0 1 2 3 4 | shuf
  )

  for exclusion_count in "${scenario_order[@]}"; do
    excluded_authorities="$(excluded_for_count "${exclusion_count}")"

    for scenario_run in $(seq 1 20); do
      report="$(
        ASTRA_EXCLUDED_AUTHORITIES="${excluded_authorities}" \
          "${client}"
      )"

      jq -c \
        --argjson batch "${batch}" \
        --argjson scenario_run "${scenario_run}" \
        --argjson exclusion_count "${exclusion_count}" \
        '. + {
          experiment_profile: "controlled-policy-exclusion",
          client_process_mode: "one-authorization-per-fresh-client-process",
          physical_outage_smoke_recorded_separately: true,
          batch: $batch,
          scenario_run: $scenario_run,
          controlled_exclusion_count: $exclusion_count
        }' <<< "${report}" >> "${result}"
    done
  done
done

jq -e -s '
  length == 500
  and all(.[];
    .success == true
    and .threshold == 3
    and .configured_authorities == 7
    and (.excluded_authorities | length) == .controlled_exclusion_count
    and .experiment_profile == "controlled-policy-exclusion"
  )
  and (
    sort_by(.controlled_exclusion_count)
    | group_by(.controlled_exclusion_count)
    | length == 5
  )
  and (
    sort_by(.controlled_exclusion_count)
    | group_by(.controlled_exclusion_count)
    | all(.[]; length == 100)
  )
' "${result}"

sha256sum "${result}"
