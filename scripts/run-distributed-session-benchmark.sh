#!/usr/bin/env bash
set -euo pipefail

repetitions="${ASTRA_SESSION_BENCHMARK_REPETITIONS:-100}"
output="${ASTRA_SESSION_BENCHMARK_OUTPUT:-/home/astraadmin/astra-pq/results/distributed-session-100.jsonl}"

if [[ ! "${repetitions}" =~ ^[1-9][0-9]*$ ]]; then
  echo "ASTRA_SESSION_BENCHMARK_REPETITIONS must be a positive integer" >&2
  exit 2
fi

umask 077
mkdir -p "$(dirname "${output}")"
temporary="${output}.partial.$$"
trap 'rm -f "${temporary}"' EXIT

ASTRA_SESSION_REPETITIONS="${repetitions}" \
ASTRA_GOVERNANCE_BUNDLE="${ASTRA_GOVERNANCE_BUNDLE:-/home/astraadmin/astra-pq/config/governance/governance-bundle.json}" \
ASTRA_GOVERNANCE_PREVIOUS_STATE="${ASTRA_GOVERNANCE_PREVIOUS_STATE:-/home/astraadmin/astra-pq/results/iota-live-governance-state-epoch1.json}" \
ASTRA_INITIATOR_SIGNING_KEY=/home/astraadmin/astra-provisioning/gateway-keys-v1/gateway-a/request-signing.sk \
ASTRA_INITIATOR_SIGNING_PUBLIC_KEY=/home/astraadmin/astra-provisioning/gateway-keys-v1/gateway-a/request-signing.pk \
ASTRA_RESPONDER_SIGNING_PUBLIC_KEY=/home/astraadmin/astra-provisioning/gateway-keys-v1/gateway-b/request-signing.pk \
ASTRA_RESPONDER_KEM_PUBLIC=/home/astraadmin/astra-provisioning/responder-kem-v1/encapsulation.pk \
ASTRA_AUTHORITY_PUBLIC_KEY_ROOT=/home/astraadmin/astra-pq/config/authority-public-keys \
ASTRA_AUTHORITY_ENDPOINTS=a1=172.16.64.11:7443,a2=172.16.64.12:7443,a3=172.16.64.13:7443 \
ASTRA_SESSION_RESPONDER_ENDPOINT=172.16.64.12:7553 \
/home/astraadmin/astra-pq/bin/astra-session-client \
  > "${temporary}"

jq -e -s \
  --argjson expected "${repetitions}" \
  '
    length == $expected
    and all(
      .[];
      .success == true
      and .risk_class == "R3"
      and .clause_count == 4
      and .evidence_count == 6
      and .session_key_exported == false
      and .bidirectional_key_confirmation == true
    )
  ' \
  "${temporary}" \
  > /dev/null

mv "${temporary}" "${output}"
trap - EXIT
sha256sum "${output}"
