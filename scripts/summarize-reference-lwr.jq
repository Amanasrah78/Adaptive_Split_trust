def stats(values):
  (values | sort) as $s |
  {
    samples: ($s | length),
    minimum_ns: $s[0],
    median_ns: $s[(($s | length) / 2 | floor)],
    p95_ns: $s[((($s | length) * 0.95 | ceil) - 1)],
    p99_ns: $s[((($s | length) * 0.99 | ceil) - 1)],
    maximum_ns: $s[-1],
    mean_ns: (($s | add) / ($s | length))
  };

group_by([.output_components, .threshold]) |
map(
  . as $records |
  {
    output_components: $records[0].output_components,
    nominal_output_bits: $records[0].nominal_output_bits,
    threshold: $records[0].threshold,
    raw_share_bytes_per_authority:
      $records[0].raw_share_bytes_per_authority,
    partial_payload_bytes_per_authority:
      $records[0].partial_payload_bytes_per_authority,
    mismatched_components:
      ([$records[].mismatched_components] | add),
    share_setup: stats([$records[].share_setup_ns]),
    partial_evaluations_sequential:
      stats([$records[].partial_evaluations_sequential_ns]),
    slowest_partial_evaluation:
      stats([$records[].slowest_partial_evaluation_ns]),
    final_combination:
      stats([$records[].final_combination_ns]),
    sequential_total:
      stats([$records[].sequential_total_ns]),
    parallel_computation_model:
      stats([$records[].parallel_computation_model_ns])
  }
) |
{
  schema: "astra-pq-pqdprf-same-host-summary-v1",
  units: "nanoseconds",
  reference_commit: "e520c669c16160d802c0d86b3034310750277899",
  reference_kernel: "portable NTL reproduction of the LWR arithmetic",
  comparability_limit:
    "This reproduces the reference arithmetic, not the complete cryptoTools/PQ-DiSE application.",
  configurations: .
}
