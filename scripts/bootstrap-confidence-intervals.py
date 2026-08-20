#!/usr/bin/env python3
"""Compute reproducible percentile-bootstrap intervals for ASTRA-PQ results."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import random
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable, Iterable


SCHEMA = "astra-pq-bootstrap-confidence-intervals-v1"
DEFAULT_RESAMPLES = 5_000
DEFAULT_SEED = 20_260_820


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number} is not a JSON object")
            records.append(value)
    if not records:
        raise ValueError(f"{path} contains no records")
    return records


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def median(sorted_values: list[float]) -> float:
    return sorted_values[len(sorted_values) // 2]


def nearest_rank(sorted_values: list[float], probability: float) -> float:
    index = max(0, math.ceil(len(sorted_values) * probability) - 1)
    return sorted_values[index]


def interval(sorted_estimates: list[float], confidence: float) -> tuple[float, float]:
    alpha = 1.0 - confidence
    lower_index = max(0, math.floor((alpha / 2.0) * len(sorted_estimates)))
    upper_index = min(
        len(sorted_estimates) - 1,
        math.ceil((1.0 - alpha / 2.0) * len(sorted_estimates)) - 1,
    )
    return sorted_estimates[lower_index], sorted_estimates[upper_index]


def bootstrap_quantiles(
    values: list[float],
    resamples: int,
    confidence: float,
    rng: random.Random,
) -> dict[str, Any]:
    if not values:
        raise ValueError("cannot bootstrap an empty sample")
    ordered = sorted(values)
    sample_count = len(ordered)
    medians: list[float] = []
    p95_values: list[float] = []
    for _ in range(resamples):
        bootstrap_sample = sorted(
            ordered[rng.randrange(sample_count)] for _ in range(sample_count)
        )
        medians.append(median(bootstrap_sample))
        p95_values.append(nearest_rank(bootstrap_sample, 0.95))
    medians.sort()
    p95_values.sort()
    median_lower, median_upper = interval(medians, confidence)
    p95_lower, p95_upper = interval(p95_values, confidence)
    return {
        "samples": sample_count,
        "minimum": ordered[0],
        "median": median(ordered),
        "median_ci_lower": median_lower,
        "median_ci_upper": median_upper,
        "p95": nearest_rank(ordered, 0.95),
        "p95_ci_lower": p95_lower,
        "p95_ci_upper": p95_upper,
        "p99": nearest_rank(ordered, 0.99),
        "maximum": ordered[-1],
        "mean": sum(ordered) / sample_count,
    }


def rounded(value: Any) -> Any:
    if isinstance(value, float):
        return round(value, 6)
    return value


def make_row(
    experiment: str,
    configuration: dict[str, Any],
    metric: str,
    unit: str,
    values: Iterable[float | int],
    scale: float,
    resamples: int,
    confidence: float,
    rng: random.Random,
) -> dict[str, Any]:
    scaled = [float(value) / scale for value in values]
    statistics = bootstrap_quantiles(scaled, resamples, confidence, rng)
    return {
        "experiment": experiment,
        "configuration": configuration,
        "metric": metric,
        "unit": unit,
        **{key: rounded(value) for key, value in statistics.items()},
    }


def grouped(
    records: Iterable[dict[str, Any]],
    key_function: Callable[[dict[str, Any]], tuple[Any, ...]],
) -> list[tuple[tuple[Any, ...], list[dict[str, Any]]]]:
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        groups[key_function(record)].append(record)
    return sorted(groups.items(), key=lambda item: tuple(str(value) for value in item[0]))


def build_rows(
    root: Path,
    resamples: int,
    confidence: float,
    seed: int,
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    results = root / "results"
    input_files = [
        results / "primitive-1000.jsonl",
        results / "synthesis-scale-100.jsonl",
        results / "distributed-cold-connection-randomized-100.jsonl",
        results / "distributed-persistent-randomized-100.jsonl",
        results / "adaptive-session-balanced-100.jsonl",
        results / "signature-baselines-balanced-100.jsonl",
        results / "astra-pq-threshold3-comparison-100.jsonl",
        results / "concurrent-authorization-curve.jsonl",
    ]
    missing = [str(path) for path in input_files if not path.is_file()]
    if missing:
        raise FileNotFoundError("missing input files: " + ", ".join(missing))
    provenance = [
        {
            "path": str(path.relative_to(root)),
            "sha256": sha256(path),
        }
        for path in input_files
    ]
    rng = random.Random(seed)
    rows: list[dict[str, Any]] = []

    primitive = read_jsonl(input_files[0])
    operations = sorted(primitive[0]["timing_ns"])
    for operation in operations:
        rows.append(
            make_row(
                "primitive",
                {"operation": operation},
                "duration",
                "us",
                (record["timing_ns"][operation] for record in primitive),
                1_000.0,
                resamples,
                confidence,
                rng,
            )
        )

    synthesis = read_jsonl(input_files[1])
    for key, records in grouped(
        synthesis,
        lambda record: (
            record["population"],
            record["risk_class"],
            record["additional_required_roles"],
            record["success"],
        ),
    ):
        population, risk_class, roles, success = key
        rows.append(
            make_row(
                "synthesis-scale",
                {
                    "population": population,
                    "risk_class": risk_class,
                    "additional_required_roles": roles,
                    "outcome": "success" if success else "intentional-fail-closed",
                },
                "synthesis_duration",
                "us",
                (record["synthesis_ns"] for record in records),
                1_000.0,
                resamples,
                confidence,
                rng,
            )
        )

    for experiment, path in [
        ("distributed-cold", input_files[2]),
        ("distributed-persistent", input_files[3]),
    ]:
        records = read_jsonl(path)
        for (threshold,), samples in grouped(records, lambda record: (record["threshold"],)):
            rows.append(
                make_row(
                    experiment,
                    {"threshold": threshold},
                    "authorization_total",
                    "us",
                    (
                        record["timing_us"]["distributed_authorization_total"]
                        for record in samples
                    ),
                    1.0,
                    resamples,
                    confidence,
                    rng,
                )
            )

    adaptive = read_jsonl(input_files[4])
    for (risk_class,), records in grouped(adaptive, lambda record: (record["risk_class"],)):
        rows.append(
            make_row(
                "adaptive-session",
                {"risk_class": risk_class},
                "session_total",
                "us",
                (record["timing_us"]["total"] for record in records),
                1.0,
                resamples,
                confidence,
                rng,
            )
        )

    baselines = read_jsonl(input_files[5])
    for (profile,), records in grouped(
        baselines, lambda record: (record["baseline_profile"],)
    ):
        rows.append(
            make_row(
                "authorization-baseline",
                {"profile": profile},
                "authorization_total",
                "us",
                (record["timing_us"]["authorization_total"] for record in records),
                1.0,
                resamples,
                confidence,
                rng,
            )
        )

    astra_comparison = read_jsonl(input_files[6])
    rows.append(
        make_row(
            "authorization-baseline",
            {"profile": "astra-pq-threshold-3"},
            "authorization_total",
            "us",
            (
                record["timing_us"]["distributed_authorization_total"]
                for record in astra_comparison
            ),
            1.0,
            resamples,
            confidence,
            rng,
        )
    )

    concurrency = read_jsonl(input_files[7])
    for (level,), records in grouped(
        concurrency, lambda record: (record["concurrency_level"],)
    ):
        rows.append(
            make_row(
                "concurrent-authorization",
                {"concurrency_level": level},
                "authorization_total",
                "us",
                (
                    record["timing_us"]["distributed_authorization_total"]
                    for record in records
                ),
                1.0,
                resamples,
                confidence,
                rng,
            )
        )

    return rows, provenance


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fieldnames = [
        "experiment",
        "configuration",
        "metric",
        "unit",
        "samples",
        "minimum",
        "median",
        "median_ci_lower",
        "median_ci_upper",
        "p95",
        "p95_ci_lower",
        "p95_ci_upper",
        "p99",
        "maximum",
        "mean",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            output = dict(row)
            output["configuration"] = json.dumps(
                row["configuration"], sort_keys=True, separators=(",", ":")
            )
            writer.writerow(output)


def self_test() -> None:
    values = [1.0, 2.0, 3.0, 4.0, 5.0]
    assert median(values) == 3.0
    assert nearest_rank(values, 0.95) == 5.0
    first = bootstrap_quantiles(values, 200, 0.95, random.Random(7))
    second = bootstrap_quantiles(values, 200, 0.95, random.Random(7))
    assert first == second
    assert first["median_ci_lower"] <= first["median"] <= first["median_ci_upper"]


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
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
    root = arguments.root.resolve()
    rows, provenance = build_rows(
        root,
        arguments.resamples,
        arguments.confidence,
        arguments.seed,
    )
    output = {
        "schema": SCHEMA,
        "method": "nonparametric percentile bootstrap",
        "confidence_level": arguments.confidence,
        "resamples": arguments.resamples,
        "seed": arguments.seed,
        "quantile_definition": (
            "upper middle order statistic for median; nearest-rank p95 and p99"
        ),
        "sampling_assumption": (
            "request observations are treated as exchangeable within each configuration; "
            "worker and temporal clustering are not modeled"
        ),
        "outlier_removal": False,
        "input_artifacts": provenance,
        "row_count": len(rows),
        "rows": rows,
    }
    json_path = root / "results" / "bootstrap-confidence-intervals.json"
    csv_path = root / "results" / "bootstrap-confidence-intervals.csv"
    with json_path.open("w", encoding="utf-8") as handle:
        json.dump(output, handle, indent=2, sort_keys=False)
        handle.write("\n")
    write_csv(csv_path, rows)
    print(json.dumps({"rows": len(rows), "json": str(json_path), "csv": str(csv_path)}))


if __name__ == "__main__":
    main()
