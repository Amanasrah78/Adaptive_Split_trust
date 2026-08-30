#!/usr/bin/env python3
"""Bootstrap confidence intervals for live-IOTA governance latency."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import random
from collections import defaultdict
from pathlib import Path
from typing import Any


SCHEMA = "astra-pq-live-iota-latency-bootstrap-v1"
INPUT_SCHEMA = "astra-pq-live-iota-latency-v1"
DEFAULT_RESAMPLES = 5_000
DEFAULT_SEED = 20_260_830


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_records(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            record = json.loads(line)
            if not isinstance(record, dict):
                raise ValueError(f"{path}:{line_number} is not a JSON object")
            if record.get("schema") != INPUT_SCHEMA:
                raise ValueError(f"{path}:{line_number} has an unexpected schema")
            if record.get("success") is not True:
                raise ValueError(f"{path}:{line_number} is not successful")
            elapsed = record.get("elapsed_us")
            if not isinstance(elapsed, int) or elapsed < 0:
                raise ValueError(f"{path}:{line_number} has invalid elapsed_us")
            records.append(record)
    if not records:
        raise ValueError(f"{path} contains no records")
    return records


def empirical_quantile(sorted_values: list[float], probability: float) -> float:
    """Match the benchmark jq summary: floor((n - 1) * probability)."""
    index = math.floor((len(sorted_values) - 1) * probability)
    return sorted_values[index]


def confidence_interval(
    sorted_estimates: list[float], confidence: float
) -> tuple[float, float]:
    alpha = 1.0 - confidence
    lower = max(0, math.floor((alpha / 2.0) * len(sorted_estimates)))
    upper = min(
        len(sorted_estimates) - 1,
        math.ceil((1.0 - alpha / 2.0) * len(sorted_estimates)) - 1,
    )
    return sorted_estimates[lower], sorted_estimates[upper]


def bootstrap(
    values: list[float],
    resamples: int,
    confidence: float,
    rng: random.Random,
) -> dict[str, float | int | list[float]]:
    ordered = sorted(values)
    count = len(ordered)
    median_estimates: list[float] = []
    p95_estimates: list[float] = []

    for _ in range(resamples):
        sample = sorted(ordered[rng.randrange(count)] for _ in range(count))
        median_estimates.append(empirical_quantile(sample, 0.50))
        p95_estimates.append(empirical_quantile(sample, 0.95))

    median_estimates.sort()
    p95_estimates.sort()
    median_interval = confidence_interval(median_estimates, confidence)
    p95_interval = confidence_interval(p95_estimates, confidence)

    return {
        "samples": count,
        "minimum_us": ordered[0],
        "median_us": empirical_quantile(ordered, 0.50),
        "median_ci_95_us": list(median_interval),
        "p95_us": empirical_quantile(ordered, 0.95),
        "p95_ci_95_us": list(p95_interval),
        "p99_us": empirical_quantile(ordered, 0.99),
        "maximum_us": ordered[-1],
        "mean_us": sum(ordered) / count,
    }


def rounded(value: Any) -> Any:
    if isinstance(value, float):
        return round(value, 6)
    if isinstance(value, list):
        return [rounded(item) for item in value]
    return value


def analyze(
    input_path: Path,
    resamples: int,
    confidence: float,
    seed: int,
) -> dict[str, Any]:
    records = read_records(input_path)
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        groups[str(record["profile"])].append(record)

    rng = random.Random(seed)
    profiles = []
    for profile in sorted(groups):
        group = groups[profile]
        statistics = bootstrap(
            [float(record["elapsed_us"]) for record in group],
            resamples,
            confidence,
            rng,
        )
        profiles.append(
            {
                "profile": profile,
                "rpc_services": sorted(
                    {int(record["rpc_services"]) for record in group}
                ),
                "network_calls_per_sample": sorted(
                    {int(record["network_calls"]) for record in group}
                ),
                **{key: rounded(value) for key, value in statistics.items()},
            }
        )

    return {
        "schema": SCHEMA,
        "method": "nonparametric percentile bootstrap",
        "confidence_level": confidence,
        "resamples": resamples,
        "seed": seed,
        "quantile_definition": "ordered sample at floor((n-1)*p)",
        "sampling_assumption": (
            "observations are treated as exchangeable within each profile; "
            "temporal dependence and shared RPC administration are not modeled"
        ),
        "outlier_removal": False,
        "session_critical_path": False,
        "rpc_administrative_independence": False,
        "input_artifact": {
            "path": str(input_path),
            "sha256": sha256(input_path),
            "records": len(records),
        },
        "profiles": profiles,
    }


def write_csv(path: Path, profiles: list[dict[str, Any]]) -> None:
    fields = [
        "profile",
        "samples",
        "minimum_us",
        "median_us",
        "median_ci_95_lower_us",
        "median_ci_95_upper_us",
        "p95_us",
        "p95_ci_95_lower_us",
        "p95_ci_95_upper_us",
        "p99_us",
        "maximum_us",
        "mean_us",
    ]
    with path.open("x", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for profile in profiles:
            writer.writerow(
                {
                    "profile": profile["profile"],
                    "samples": profile["samples"],
                    "minimum_us": profile["minimum_us"],
                    "median_us": profile["median_us"],
                    "median_ci_95_lower_us": profile["median_ci_95_us"][0],
                    "median_ci_95_upper_us": profile["median_ci_95_us"][1],
                    "p95_us": profile["p95_us"],
                    "p95_ci_95_lower_us": profile["p95_ci_95_us"][0],
                    "p95_ci_95_upper_us": profile["p95_ci_95_us"][1],
                    "p99_us": profile["p99_us"],
                    "maximum_us": profile["maximum_us"],
                    "mean_us": profile["mean_us"],
                }
            )


def self_test() -> None:
    values = [1.0, 2.0, 3.0, 4.0]
    assert empirical_quantile(values, 0.50) == 2.0
    assert empirical_quantile(values, 0.95) == 3.0
    first = bootstrap(values, 500, 0.95, random.Random(7))
    second = bootstrap(values, 500, 0.95, random.Random(7))
    assert first == second
    interval = first["median_ci_95_us"]
    assert isinstance(interval, list)
    assert interval[0] <= first["median_us"] <= interval[1]


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path)
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--csv-output", type=Path)
    parser.add_argument("--resamples", type=int, default=DEFAULT_RESAMPLES)
    parser.add_argument("--confidence", type=float, default=0.95)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> None:
    arguments = parse_arguments()
    if arguments.self_test:
        self_test()
        print("self-test passed")
        return
    if arguments.resamples < 100:
        raise ValueError("at least 100 bootstrap resamples are required")
    if not 0.0 < arguments.confidence < 1.0:
        raise ValueError("confidence must be between zero and one")
    if arguments.input is None:
        raise ValueError("--input is required")
    if arguments.json_output is None:
        raise ValueError("--json-output is required")
    if arguments.csv_output is None:
        raise ValueError("--csv-output is required")
    result = analyze(
        arguments.input,
        arguments.resamples,
        arguments.confidence,
        arguments.seed,
    )
    with arguments.json_output.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
        handle.write("\n")
    write_csv(arguments.csv_output, result["profiles"])
    print(
        json.dumps(
            {
                "profiles": len(result["profiles"]),
                "json": str(arguments.json_output),
                "csv": str(arguments.csv_output),
            }
        )
    )


if __name__ == "__main__":
    main()
