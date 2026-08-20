#!/usr/bin/env bash
set -euo pipefail

root=/home/astraadmin/astra-pq
client="${root}/bin/astra-signature-baseline-client"
result="${ASTRA_BASELINE_RESULT:-${root}/results/signature-baselines-balanced-100.jsonl}"
blocks="${ASTRA_BASELINE_BLOCKS:-10}"
samples_per_profile_per_block="${ASTRA_BASELINE_SAMPLES_PER_BLOCK:-10}"

if [[ -e "${result}" ]]; then
  echo "refusing to overwrite existing result: ${result}" >&2
  exit 1
fi

mkdir -p "$(dirname "${result}")"
temporary="$(mktemp "$(dirname "${result}")/.signature-baselines.XXXXXX")"
chmod 600 "${temporary}"
trap 'rm -f "${temporary}"' EXIT

common_environment=(
  "ASTRA_REPETITIONS=${samples_per_profile_per_block}"
  "ASTRA_GATEWAY_ID=gateway-a"
  "ASTRA_GOVERNANCE_BUNDLE=${root}/config/governance/governance-bundle.json"
  "ASTRA_GATEWAY_SIGNING_KEY=${root}/secrets/gateway-request/request-signing.sk"
  "ASTRA_GATEWAY_PUBLIC_KEY=${root}/secrets/gateway-request/request-signing.pk"
  "ASTRA_AUTHORITY_PUBLIC_KEY_ROOT=${root}/config/authority-public-keys"
  "ASTRA_BASELINE_ENDPOINTS=a1=172.16.64.11:7663,a2=172.16.64.12:7663,a3=172.16.64.13:7663"
)

run_profile() {
  local block="$1"
  local order="$2"
  local profile="$3"

  env \
    "${common_environment[@]}" \
    "ASTRA_BASELINE_PROFILE=${profile}" \
    "${client}" \
    | jq -c \
        --argjson benchmark_block "${block}" \
        --argjson within_block_profile_order "${order}" \
        '. + {
          benchmark_block: $benchmark_block,
          within_block_profile_order: $within_block_profile_order
        }' \
    >> "${temporary}"
}

for ((block = 1; block <= blocks; block++)); do
  if ((block % 2 == 1)); then
    run_profile "${block}" 1 centralized
    run_profile "${block}" 2 static-quorum
  else
    run_profile "${block}" 1 static-quorum
    run_profile "${block}" 2 centralized
  fi
done

expected_per_profile=$((blocks * samples_per_profile_per_block))
expected_total=$((expected_per_profile * 2))

jq -e -s \
  --argjson expected_total "${expected_total}" \
  --argjson expected_per_profile "${expected_per_profile}" \
  '
    length == $expected_total
    and all(.success == true)
    and all(.schema == "astra-pq-signature-authorization-baseline-v1")
    and all(.security_equivalent_to_astra_pq == false)
    and all(.distributed_authorization_secret == false)
    and ([.[] | select(.baseline_profile == "centralized")] | length
         == $expected_per_profile)
    and ([.[] | select(.baseline_profile == "static-quorum")] | length
         == $expected_per_profile)
    and ([.[] | select(
          .baseline_profile == "centralized"
          and .required_approvals == 1
          and .authority_ids == ["a2"]
        )] | length == $expected_per_profile)
    and ([.[] | select(
          .baseline_profile == "static-quorum"
          and .required_approvals == 3
          and .authority_ids == ["a1", "a2", "a3"]
        )] | length == $expected_per_profile)
  ' \
  "${temporary}" >/dev/null

mv "${temporary}" "${result}"
trap - EXIT
sha256sum "${result}"
