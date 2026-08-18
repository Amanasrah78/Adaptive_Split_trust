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
  schema: "astra-pq-adaptive-session-responder-summary-v1",
  total_samples: length,
  session_key_exported_values: ([.[].session_key_exported] | unique),
  confirmation_values: ([.[].bidirectional_key_confirmation] | unique),
  risks: (
    group_by(.risk_class)
    | map(
        . as $samples
        | {
            risk_class: $samples[0].risk_class,
            samples: ($samples | length),
            clause_count: ([$samples[].clause_count] | unique | first),
            evidence_count: ([$samples[].evidence_count] | unique | first),
            total_us: ([$samples[].timing_us.total] | stats),
            request_verification_us: (
              [$samples[].timing_us.request_verification] | stats
            ),
            kem_decapsulation_us: (
              [$samples[].timing_us.kem_decapsulation] | stats
            ),
            session_establishment_us: (
              [$samples[].timing_us.session_establishment] | stats
            ),
            finish_verification_us: (
              [$samples[].timing_us.finish_verification] | stats
            )
          }
      )
  )
}
