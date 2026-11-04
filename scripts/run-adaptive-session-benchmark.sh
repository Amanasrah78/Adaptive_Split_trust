#!/usr/bin/env bash
set -euo pipefail

authorization_mode="${ASTRA_AUTHORIZATION_MODE:-lwr}"
if [[ "${authorization_mode}" != "lwr" && "${authorization_mode}" != "seb" ]]; then
  echo "ASTRA_AUTHORIZATION_MODE must be lwr or seb" >&2
  exit 2
fi
blocks="${ASTRA_ADAPTIVE_BLOCKS:-5}"
repetitions_per_block="${ASTRA_ADAPTIVE_REPETITIONS_PER_BLOCK:-20}"
output="${ASTRA_ADAPTIVE_OUTPUT:-/home/astraadmin/astra-pq/results/adaptive-session-balanced-${authorization_mode}-100.jsonl}"
governance_bundle="${ASTRA_ADAPTIVE_GOVERNANCE_BUNDLE:-/home/astraadmin/astra-pq/config/governance/governance-bundle.json}"
expected_live_iota_claim="${ASTRA_ADAPTIVE_EXPECT_LIVE_IOTA_CLAIM:-false}"
expected_network_id="${ASTRA_ADAPTIVE_EXPECT_NETWORK_ID:-}"

if [[ "${expected_live_iota_claim}" != "true" &&
      "${expected_live_iota_claim}" != "false" ]]; then
  echo "ASTRA_ADAPTIVE_EXPECT_LIVE_IOTA_CLAIM must be true or false" >&2
  exit 2
fi

for value in "${blocks}" "${repetitions_per_block}"; do
  if [[ ! "${value}" =~ ^[1-9][0-9]*$ ]]; then
    echo "adaptive benchmark counts must be positive integers" >&2
    exit 2
  fi
done

risks=(R0 R1 R2 R3 R4)
expected_per_risk=$((blocks * repetitions_per_block))
expected_total=$((expected_per_risk * ${#risks[@]}))

umask 077
mkdir -p "$(dirname "${output}")"
temporary="${output}.partial.$$"
block_output="${temporary}.block"
trap 'rm -f "${temporary}" "${block_output}"' EXIT
: > "${temporary}"

sequence=0
for ((block = 0; block < blocks; block++)); do
  for ((step = 0; step < ${#risks[@]}; step++)); do
    index=$(((block + step) % ${#risks[@]}))
    risk="${risks[index]}"

    ASTRA_SESSION_RISK="${risk}" \
    ASTRA_AUTHORIZATION_MODE="${authorization_mode}" \
    ASTRA_SESSION_REPETITIONS="${repetitions_per_block}" \
    ASTRA_GOVERNANCE_BUNDLE="${governance_bundle}" \
    ASTRA_INITIATOR_SIGNING_KEY=/home/astraadmin/astra-pq/secrets/gateway-request/request-signing.sk \
    ASTRA_INITIATOR_SIGNING_PUBLIC_KEY=/home/astraadmin/astra-pq/secrets/gateway-request/request-signing.pk \
    ASTRA_RESPONDER_SIGNING_PUBLIC_KEY=/home/astraadmin/astra-pq/config/gateway-public-keys/gateway-b.pk \
    ASTRA_RESPONDER_KEM_PUBLIC=/home/astraadmin/astra-pq/config/responder-kem/gateway-b.pk \
    ASTRA_AUTHORITY_PUBLIC_KEY_ROOT=/home/astraadmin/astra-pq/config/authority-public-keys \
    ASTRA_AUTHORITY_ENDPOINTS=a1=172.16.64.11:7443,a2=172.16.64.12:7443,a3=172.16.64.13:7443,a4=172.16.64.14:7443 \
    ASTRA_SESSION_RESPONDER_ENDPOINT=172.16.64.12:7553 \
    /home/astraadmin/astra-pq/bin/astra-session-client \
      > "${block_output}"

    sequence=$((sequence + 1))
    jq -c \
      --argjson benchmark_block "$((block + 1))" \
      --argjson benchmark_sequence "${sequence}" \
      --arg benchmark_risk "${risk}" \
      '. + {
        benchmark_block: $benchmark_block,
        benchmark_sequence: $benchmark_sequence,
        benchmark_risk: $benchmark_risk,
        authority_connection_setup_in_timing: false,
        responder_connection_setup_in_timing: true
      }' \
      "${block_output}" \
      >> "${temporary}"
  done
done

jq -e -s \
  --argjson expected_total "${expected_total}" \
  --argjson expected_per_risk "${expected_per_risk}" \
  --argjson expected_live_iota_claim "${expected_live_iota_claim}" \
  --arg expected_mode "${authorization_mode}" \
  --arg expected_network_id "${expected_network_id}" \
  '
    length == $expected_total
    and ([.[] | select(.risk_class == "R0")] | length == $expected_per_risk)
    and ([.[] | select(.risk_class == "R1")] | length == $expected_per_risk)
    and ([.[] | select(.risk_class == "R2")] | length == $expected_per_risk)
    and ([.[] | select(.risk_class == "R3")] | length == $expected_per_risk)
    and ([.[] | select(.risk_class == "R4")] | length == $expected_per_risk)
    and all(.[];
      .success == true
      and .authorization_mode == $expected_mode
      and .live_iota_claim == $expected_live_iota_claim
      and (
        $expected_network_id == ""
        or .governance_network_id == $expected_network_id
      )
      and .session_key_exported == false
      and .bidirectional_key_confirmation == true
      and .risk_class == .benchmark_risk
      and (
        if .risk_class == "R0" then .clause_count == 1 and .evidence_count == 1
        elif .risk_class == "R1" then .clause_count == 2 and .evidence_count == 3
        elif .risk_class == "R2" then .clause_count == 3 and .evidence_count == 4
        elif .risk_class == "R3" then .clause_count == 4 and .evidence_count == 6
        elif .risk_class == "R4" then .clause_count == 5 and .evidence_count == 8
        else false
        end
      )
    )
  ' \
  "${temporary}" \
  > /dev/null

rm -f "${block_output}"
mv "${temporary}" "${output}"
trap - EXIT
sha256sum "${output}"
