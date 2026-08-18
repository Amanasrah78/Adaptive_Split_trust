def stats:
  sort as $s
  | ($s | length) as $n
  | {
      samples: $n,
      minimum: $s[0],
      median: $s[($n / 2 | floor)],
      p95: $s[(($n * 0.95 | ceil) - 1)],
      p99: $s[(($n * 0.99 | ceil) - 1)],
      maximum: $s[-1],
      mean: (($s | add) / $n)
    };

{
  schema: "astra-pq-adaptive-session-balanced-summary-v1",
  total_samples: length,
  design: {
    risk_classes: ["R0", "R1", "R2", "R3", "R4"],
    blocks: ([.[].benchmark_block] | unique | length),
    samples_per_risk: 100,
    order: "cyclically rotated risk order across blocks",
    authority_connection_setup_in_timing: false,
    responder_connection_setup_in_timing: true
  },
  risks: (
    group_by(.risk_class)
    | map(
        . as $samples
        | {
            risk_class: $samples[0].risk_class,
            samples: ($samples | length),
            clause_count: ([$samples[].clause_count] | unique | first),
            evidence_count: ([$samples[].evidence_count] | unique | first),
            authority_count: (
              [$samples[0].contributors | to_entries[] | .value[]]
              | unique
              | length
            ),
            contributors: ([$samples[].contributors] | unique),
            total_us: ([$samples[].timing_us.total] | stats),
            authority_collection_us: (
              [$samples[].timing_us.authority_collection] | stats
            ),
            authority_request_signing_us: (
              [$samples[].timing_us.authority_request_signing] | stats
            ),
            evidence_verification_us: (
              [$samples[].timing_us.evidence_verification] | stats
            ),
            initiator_session_establishment_us: (
              [$samples[].timing_us.initiator_session_establishment] | stats
            ),
            responder_handshake_us: (
              [$samples[].timing_us.responder_handshake] | stats
            ),
            kem_encapsulation_us: (
              [$samples[].timing_us.kem_encapsulation] | stats
            ),
            policy_synthesis_us: (
              [$samples[].timing_us.policy_synthesis] | stats
            ),
            gateway_session_request_bytes: (
              [$samples[].gateway_session_request_bytes] | stats
            ),
            authority_request_bytes_total: (
              [$samples[].authority_request_bytes_total] | stats
            ),
            authority_response_bytes_total: (
              [$samples[].authority_response_bytes_total] | stats
            )
          }
      )
  )
}
