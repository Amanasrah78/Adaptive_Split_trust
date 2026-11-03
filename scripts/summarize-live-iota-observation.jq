def percentile($values; $p):
  ($values | sort) as $sorted
  | $sorted[
      (((($sorted | length) - 1) * $p) | floor)
    ];

def statistics($values):
  {
    samples: ($values | length),
    minimum_us: ($values | min),
    median_us: percentile($values; 0.50),
    p95_us: percentile($values; 0.95),
    p99_us: percentile($values; 0.99),
    maximum_us: ($values | max),
    mean_us: (($values | add) / ($values | length))
  };

sort_by(.profile, .run)
| group_by(.profile)
| map(
    . as $records
    | {
        profile: $records[0].profile,
        success: all($records[]; .success == true),
        rpc_services: ($records | map(.rpc_services) | unique),
        network_calls_per_sample:
          ($records | map(.network_calls) | unique),
        endpoint_orders:
          ($records | map(.endpoint_order) | unique),
        administratively_independent:
          ($records | map(.administratively_independent) | unique),
        object_versions:
          ($records | map(.object_version) | unique),
        checkpoint_hashes:
          ($records | map(.checkpoint_hash) | unique),
        latency: statistics($records | map(.elapsed_us))
      }
  ) as $profiles
| {
    schema: "astra-pq-live-iota-latency-summary-v1",
    units: "microseconds",
    total_samples: ($profiles | map(.latency.samples) | add),
    samples_per_profile:
      ($profiles | map(.latency.samples) | unique),
    all_successful: all($profiles[]; .success == true),
    session_critical_path: false,
    rpc_administrative_independence: false,
    profiles: $profiles,
    interpretation:
      "Network observations are off-path governance synchronization costs. The two RPC services share IOTA administration and are not an independent-operator quorum."
  }
