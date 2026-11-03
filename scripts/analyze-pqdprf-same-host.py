#!/usr/bin/env python3
"""Compare ASTRA-PQ and the same-host PQDPRF LWR reference kernel.

The analysis uses deterministic nonparametric percentile bootstrap intervals.
It compares the closest available configuration: three authorities and 26
LWR output components (260 nominal reference bits versus 256 ASTRA-PQ bits).
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import random
from pathlib import Path
from typing import Callable, Iterable, Sequence


DEFAULT_SEED = 20260820
DEFAULT_RESAMPLES = 5000


def read_jsonl(path: Path) -> list[dict]:
    records = []
    with path.open("r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"invalid JSON at {path}:{line_number}: {error}") from error
            if not isinstance(value, dict):
                raise ValueError(f"expected an object at {path}:{line_number}")
            records.append(value)
    if not records:
        raise ValueError(f"no records in {path}")
    return records


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def upper_median(values: Sequence[float]) -> float:
    ordered = sorted(values)
    return float(ordered[len(ordered) // 2])


def nearest_rank(values: Sequence[float], probability: float) -> float:
    ordered = sorted(values)
    index = max(0, math.ceil(len(ordered) * probability) - 1)
    return float(ordered[index])


def percentile(values: Sequence[float], probability: float) -> float:
    """Linearly interpolated percentile for bootstrap distributions."""
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(ordered[lower])
    weight = position - lower
    return float(ordered[lower] * (1.0 - weight) + ordered[upper] * weight)


def bootstrap_statistic(
    values: Sequence[float],
    statistic: Callable[[Sequence[float]], float],
    rng: random.Random,
    resamples: int,
) -> list[float]:
    count = len(values)
    return [
        statistic([values[rng.randrange(count)] for _ in range(count)])
        for _ in range(resamples)
    ]


def bootstrap_contrast(
    astra: Sequence[float],
    reference: Sequence[float],
    rng: random.Random,
    resamples: int,
) -> tuple[list[float], list[float], list[float]]:
    differences = []
    ratios = []
    reductions = []
    for _ in range(resamples):
        astra_median = upper_median(
            [astra[rng.randrange(len(astra))] for _ in range(len(astra))]
        )
        reference_median = upper_median(
            [reference[rng.randrange(len(reference))] for _ in range(len(reference))]
        )
        differences.append(astra_median - reference_median)
        ratios.append(reference_median / astra_median)
        reductions.append(100.0 * (1.0 - astra_median / reference_median))
    return differences, ratios, reductions


def ci(values: Sequence[float]) -> list[float]:
    return [percentile(values, 0.025), percentile(values, 0.975)]


def metric_comparison(
    name: str,
    astra_ns: Sequence[float],
    reference_ns: Sequence[float],
    rng: random.Random,
    resamples: int,
    comparability: str,
) -> dict:
    astra_us = [value / 1000.0 for value in astra_ns]
    reference_us = [value / 1000.0 for value in reference_ns]
    astra_median = upper_median(astra_us)
    reference_median = upper_median(reference_us)
    astra_bootstrap = bootstrap_statistic(astra_us, upper_median, rng, resamples)
    reference_bootstrap = bootstrap_statistic(
        reference_us, upper_median, rng, resamples
    )
    differences, ratios, reductions = bootstrap_contrast(
        astra_us, reference_us, rng, resamples
    )
    return {
        "metric": name,
        "unit": "microseconds",
        "astra_samples": len(astra_us),
        "reference_samples": len(reference_us),
        "astra_median_us": astra_median,
        "astra_median_ci_95_us": ci(astra_bootstrap),
        "astra_p95_us": nearest_rank(astra_us, 0.95),
        "reference_median_us": reference_median,
        "reference_median_ci_95_us": ci(reference_bootstrap),
        "reference_p95_us": nearest_rank(reference_us, 0.95),
        "astra_minus_reference_median_us": astra_median - reference_median,
        "astra_minus_reference_median_ci_95_us": ci(differences),
        "reference_over_astra_median_ratio": reference_median / astra_median,
        "reference_over_astra_median_ratio_ci_95": ci(ratios),
        "astra_reduction_vs_reference_percent": 100.0
        * (1.0 - astra_median / reference_median),
        "astra_reduction_vs_reference_ci_95_percent": ci(reductions),
        "comparability": comparability,
    }


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def write_csv(path: Path, comparisons: Iterable[dict]) -> None:
    fields = [
        "metric",
        "astra_samples",
        "reference_samples",
        "astra_median_us",
        "astra_median_ci_95_lower_us",
        "astra_median_ci_95_upper_us",
        "reference_median_us",
        "reference_median_ci_95_lower_us",
        "reference_median_ci_95_upper_us",
        "reference_over_astra_median_ratio",
        "ratio_ci_95_lower",
        "ratio_ci_95_upper",
        "astra_reduction_vs_reference_percent",
        "reduction_ci_95_lower_percent",
        "reduction_ci_95_upper_percent",
        "comparability",
    ]
    with path.open("w", encoding="utf-8", newline="") as destination:
        writer = csv.DictWriter(destination, fieldnames=fields)
        writer.writeheader()
        for item in comparisons:
            writer.writerow(
                {
                    "metric": item["metric"],
                    "astra_samples": item["astra_samples"],
                    "reference_samples": item["reference_samples"],
                    "astra_median_us": item["astra_median_us"],
                    "astra_median_ci_95_lower_us": item[
                        "astra_median_ci_95_us"
                    ][0],
                    "astra_median_ci_95_upper_us": item[
                        "astra_median_ci_95_us"
                    ][1],
                    "reference_median_us": item["reference_median_us"],
                    "reference_median_ci_95_lower_us": item[
                        "reference_median_ci_95_us"
                    ][0],
                    "reference_median_ci_95_upper_us": item[
                        "reference_median_ci_95_us"
                    ][1],
                    "reference_over_astra_median_ratio": item[
                        "reference_over_astra_median_ratio"
                    ],
                    "ratio_ci_95_lower": item[
                        "reference_over_astra_median_ratio_ci_95"
                    ][0],
                    "ratio_ci_95_upper": item[
                        "reference_over_astra_median_ratio_ci_95"
                    ][1],
                    "astra_reduction_vs_reference_percent": item[
                        "astra_reduction_vs_reference_percent"
                    ],
                    "reduction_ci_95_lower_percent": item[
                        "astra_reduction_vs_reference_ci_95_percent"
                    ][0],
                    "reduction_ci_95_upper_percent": item[
                        "astra_reduction_vs_reference_ci_95_percent"
                    ][1],
                    "comparability": item["comparability"],
                }
            )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--astra", type=Path, default=Path("results/primitive-1000.jsonl")
    )
    parser.add_argument(
        "--reference",
        type=Path,
        default=Path("results/pqdprf-reference-same-host-1000.jsonl"),
    )
    parser.add_argument(
        "--json-output",
        type=Path,
        default=Path("results/pqdprf-same-host-comparison.json"),
    )
    parser.add_argument(
        "--csv-output",
        type=Path,
        default=Path("results/pqdprf-same-host-comparison.csv"),
    )
    parser.add_argument("--resamples", type=int, default=DEFAULT_RESAMPLES)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args()
    require(args.resamples >= 1, "resamples must be positive")

    astra = read_jsonl(args.astra)
    reference_all = read_jsonl(args.reference)
    require(
        all(record.get("schema") == "astra-pq-primitive-benchmark-v1" for record in astra),
        "unexpected ASTRA-PQ input schema",
    )
    require(all(record.get("success") is True for record in astra), "failed ASTRA-PQ sample")
    require(
        all(record.get("lwr_threshold") == 3 for record in astra),
        "ASTRA-PQ primitive data are not uniformly threshold 3",
    )

    reference = [
        record
        for record in reference_all
        if record.get("threshold") == 3 and record.get("output_components") == 26
    ]
    require(len(reference) == 1000, "expected 1,000 matching reference samples")
    require(
        all(record.get("mismatched_components") == 0 for record in reference),
        "reference reconstruction mismatch detected",
    )

    rng = random.Random(args.seed)
    comparisons = [
        metric_comparison(
            "lwr_partial_evaluations_sequential",
            [record["timing_ns"]["lwr_partial_evaluations_sequential"] for record in astra],
            [record["partial_evaluations_sequential_ns"] for record in reference],
            rng,
            args.resamples,
            "Direct local sequential kernel comparison at threshold 3 and approximately 256 output bits.",
        ),
        metric_comparison(
            "lwr_combine",
            [record["timing_ns"]["lwr_combine"] for record in astra],
            [record["final_combination_ns"] for record in reference],
            rng,
            args.resamples,
            "Direct local final-combination timing, with different internal representations.",
        ),
        metric_comparison(
            "lwr_share_setup",
            [record["timing_ns"]["lwr_share_setup"] for record in astra],
            [record["share_setup_ns"] for record in reference],
            rng,
            args.resamples,
            "Structural comparison only: ASTRA-PQ provisions independent per-component shares; the reference reuses one key share.",
        ),
    ]

    astra_first = astra[0]
    reference_first = reference[0]
    astra_threshold = int(astra_first["lwr_threshold"])
    astra_share_per_authority = (
        int(astra_first["sizes"]["lwr_secret_share_bytes_total"]) // astra_threshold
    )
    astra_payload_per_authority = (
        int(astra_first["sizes"]["lwr_partial_payload_bytes_total"]) // astra_threshold
    )
    reference_share = int(reference_first["raw_share_bytes_per_authority"])
    reference_payload = int(reference_first["partial_payload_bytes_per_authority"])

    report = {
        "schema": "astra-pq-pqdprf-same-host-comparison-v1",
        "analysis": {
            "method": "nonparametric percentile bootstrap",
            "confidence_level": 0.95,
            "resamples": args.resamples,
            "seed": args.seed,
            "median_definition": "upper order statistic for even sample counts",
            "sampling_assumption": "observations are exchangeable within each implementation; temporal dependence is not modeled",
        },
        "configuration": {
            "host_relationship": "same AArch64 controller host",
            "threshold": 3,
            "astra_output_bits": 256,
            "reference_output_components": 26,
            "reference_nominal_output_bits": 260,
            "reference_commit": reference_first["reference_commit"],
            "timed_scope": "local LWR setup, sequential partial evaluation, and final combination; no transport",
        },
        "source_artifacts": {
            "astra": str(args.astra),
            "astra_sha256": sha256(args.astra),
            "reference": str(args.reference),
            "reference_sha256": sha256(args.reference),
        },
        "timings": comparisons,
        "storage_and_payload": {
            "astra_share_bytes_per_authority": astra_share_per_authority,
            "reference_share_bytes_per_authority": reference_share,
            "astra_over_reference_share_ratio": astra_share_per_authority / reference_share,
            "astra_partial_payload_bytes_per_authority": astra_payload_per_authority,
            "reference_partial_payload_bytes_per_authority": reference_payload,
            "astra_over_reference_payload_ratio": astra_payload_per_authority
            / reference_payload,
            "interpretation": "ASTRA-PQ stores independent share material per output component; the reference reuses one 1024-element key share across components.",
        },
        "comparability_limit": "This is a same-host reproduction of the published reference arithmetic kernel, not complete PQ-DiSE or cryptoTools end-to-end latency.",
    }

    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    with args.json_output.open("w", encoding="utf-8") as destination:
        json.dump(report, destination, indent=2)
        destination.write("\n")
    write_csv(args.csv_output, comparisons)

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
