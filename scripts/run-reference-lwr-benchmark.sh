#!/usr/bin/env bash
set -euo pipefail

source_file=${1:-scripts/reference-lwr-bench.cpp}
summary_filter=${2:-scripts/summarize-reference-lwr.jq}
result_root=${3:-results}
reference_root=${PQDPRF_REFERENCE_ROOT:-../PQDiSE-from-PQDPRF}
expected_commit=e520c669c16160d802c0d86b3034310750277899

test -f "${source_file}"
test -f "${summary_filter}"
test -d "${reference_root}/.git"
test "$(git -C "${reference_root}" rev-parse HEAD)" = "${expected_commit}"
test ! -e "${result_root}/pqdprf-reference-same-host-1000.jsonl"

mkdir -p target/reference-benchmark "${result_root}"

g++ \
  -O3 \
  -DNDEBUG \
  -std=c++17 \
  -Wall \
  -Wextra \
  -Werror \
  "${source_file}" \
  -lntl \
  -lgmp \
  -pthread \
  -o target/reference-benchmark/reference-lwr-bench

/usr/bin/time -v \
  -o "${result_root}/pqdprf-reference-same-host-1000-resource.txt" \
  target/reference-benchmark/reference-lwr-bench \
  > "${result_root}/pqdprf-reference-same-host-1000.jsonl"

jq -s -f "${summary_filter}" \
  "${result_root}/pqdprf-reference-same-host-1000.jsonl" \
  > "${result_root}/pqdprf-reference-same-host-1000-summary.json"

{
  echo "PQDPRF same-host reference-kernel evaluation"
  echo "Captured:"
  date --iso-8601=seconds
  echo
  echo "Reference repository:"
  git -C "${reference_root}" rev-parse HEAD
  git -C "${reference_root}" status --short
  sha256sum \
    "${reference_root}/pqdise/dEnc_tests/Compare_DPrfs.cpp" \
    "${reference_root}/pqdise/dEnc/dprf/LWR_helper.cpp"
  echo
  echo "Host:"
  uname -a
  lscpu
  echo
  echo "Compiler and libraries:"
  g++ --version
  dpkg-query -W libntl-dev libgmp-dev 2>/dev/null || true
  echo
  echo "Benchmark design:"
  echo "samples_per_threshold_per_output_width=1000"
  echo "thresholds=1,2,3,4,5,6,7"
  echo "output_components=13,26"
  echo "blocks=10"
  echo "order=cyclically_rotated_configuration_order"
  echo "warmup_samples_per_configuration=20"
  echo "input_expansion_timed=false"
  echo "network_timed=false"
  echo "outlier_removal=false"
  echo
  echo "Comparability boundary:"
  echo "portable NTL reproduction of the reference LWR arithmetic"
  echo "not the complete cryptoTools or PQ-DiSE application"
  echo "parallel_computation_model_ns is calculated, not a measured parallel execution"
  echo
  echo "Resource measurement:"
  cat "${result_root}/pqdprf-reference-same-host-1000-resource.txt"
  echo
  echo "Artifact hashes:"
  sha256sum \
    target/reference-benchmark/reference-lwr-bench \
    "${source_file}" \
    "${summary_filter}" \
    "${result_root}/pqdprf-reference-same-host-1000.jsonl" \
    "${result_root}/pqdprf-reference-same-host-1000-summary.json" \
    "${result_root}/pqdprf-reference-same-host-1000-resource.txt"
} > "${result_root}/pqdprf-reference-same-host-1000-environment.txt"

jq '{
  schema,
  units,
  reference_commit,
  configurations: [
    .configurations[] |
    {
      output_components,
      nominal_output_bits,
      threshold,
      partial_sequential_median_ns:
        .partial_evaluations_sequential.median_ns,
      slowest_partial_median_ns:
        .slowest_partial_evaluation.median_ns,
      combine_median_ns: .final_combination.median_ns,
      mismatched_components
    }
  ]
}' "${result_root}/pqdprf-reference-same-host-1000-summary.json"

sha256sum \
  "${result_root}/pqdprf-reference-same-host-1000.jsonl" \
  "${result_root}/pqdprf-reference-same-host-1000-summary.json" \
  "${result_root}/pqdprf-reference-same-host-1000-resource.txt" \
  "${result_root}/pqdprf-reference-same-host-1000-environment.txt"
