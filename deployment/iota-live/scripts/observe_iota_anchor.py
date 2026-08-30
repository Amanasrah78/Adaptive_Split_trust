#!/usr/bin/env python3
"""Observe one ASTRA-PQ governance object through independent IOTA RPCs."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


EXPECTED_TYPE_SUFFIX = "::astra_pq_governance::AstraPQGovernance"


class ObservationError(RuntimeError):
    pass


@dataclass(frozen=True)
class Endpoint:
    operator_id: str
    url: str


def rpc(endpoint: Endpoint, method: str, params: list[Any]) -> Any:
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode()
    request = urllib.request.Request(
        endpoint.url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = json.load(response)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        raise ObservationError(f"{endpoint.operator_id}: RPC request failed: {error}") from error
    if "error" in payload:
        raise ObservationError(f"{endpoint.operator_id}: RPC error: {payload['error']}")
    if "result" not in payload:
        raise ObservationError(f"{endpoint.operator_id}: RPC response has no result")
    return payload["result"]


def bytes32(value: Any, field: str) -> str:
    if not isinstance(value, list) or len(value) != 32:
        raise ObservationError(f"{field} must contain exactly 32 bytes")
    if any(not isinstance(item, int) or item < 0 or item > 255 for item in value):
        raise ObservationError(f"{field} contains an invalid byte")
    return bytes(value).hex()


def digest32_from_iota_text(value: str) -> str:
    """Map IOTA's printable transaction digest into ASTRA-PQ Digest32."""
    if not isinstance(value, str) or not value:
        raise ObservationError("previousTransaction is missing")
    return hashlib.sha3_256(value.encode("utf-8")).hexdigest()


def parse_endpoint(value: str) -> Endpoint:
    operator_id, separator, url = value.partition("=")
    if not separator or not operator_id or not url:
        raise argparse.ArgumentTypeError("endpoint must be OPERATOR_ID=URL")
    return Endpoint(operator_id, url)


def observe(endpoint: Endpoint, object_id: str, expected_package: str) -> dict[str, Any]:
    chain_id = rpc(endpoint, "iota_getChainIdentifier", [])
    result = rpc(
        endpoint,
        "iota_getObject",
        [
            object_id,
            {
                "showType": True,
                "showOwner": True,
                "showPreviousTransaction": True,
                "showContent": True,
            },
        ],
    )
    data = result.get("data") if isinstance(result, dict) else None
    if not isinstance(data, dict):
        raise ObservationError(f"{endpoint.operator_id}: object data is missing")
    if data.get("objectId") != object_id:
        raise ObservationError(f"{endpoint.operator_id}: object ID mismatch")
    object_type = data.get("type", "")
    if object_type != f"{expected_package}{EXPECTED_TYPE_SUFFIX}":
        raise ObservationError(f"{endpoint.operator_id}: unexpected object type {object_type!r}")
    content = data.get("content")
    fields = content.get("fields") if isinstance(content, dict) else None
    if not isinstance(fields, dict):
        raise ObservationError(f"{endpoint.operator_id}: Move fields are missing")
    previous_transaction = data.get("previousTransaction")
    return {
        "operator_id": endpoint.operator_id,
        "rpc_url": endpoint.url,
        "network_id": chain_id,
        "package_id": expected_package,
        "object_id": object_id,
        "object_version": int(data["version"]),
        "object_digest": data.get("digest"),
        "previous_transaction": previous_transaction,
        "transaction_digest": digest32_from_iota_text(previous_transaction),
        "package_version": int(fields["package_version"]),
        "epoch": int(fields["epoch"]),
        "predecessor_hash": bytes32(fields["predecessor_hash"], "predecessor_hash"),
        "checkpoint_hash": bytes32(fields["checkpoint_hash"], "checkpoint_hash"),
        "activation_time": int(fields["activation_time"]),
        "bundle_uri_bytes": fields["bundle_uri"],
        "bundle_uri": bytes(fields["bundle_uri"]).decode("utf-8"),
        "governance_key_set_id_bytes": fields["governance_key_set_id"],
        "governance_key_set_id": bytes(fields["governance_key_set_id"]).decode("utf-8"),
        "observed_at_unix": int(time.time()),
    }


def agreement_key(observation: dict[str, Any]) -> tuple[Any, ...]:
    return (
        observation["network_id"],
        observation["package_id"],
        observation["object_id"],
        observation["object_version"],
        observation["previous_transaction"],
        observation["package_version"],
        observation["epoch"],
        observation["predecessor_hash"],
        observation["checkpoint_hash"],
        observation["activation_time"],
        observation["bundle_uri"],
        observation["governance_key_set_id"],
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--object-id", required=True)
    parser.add_argument("--package-id", required=True)
    parser.add_argument(
        "--rpc",
        action="append",
        required=True,
        type=parse_endpoint,
        metavar="OPERATOR_ID=URL",
    )
    parser.add_argument("--required-agreement", type=int, default=2)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.required_agreement < 1:
        parser.error("--required-agreement must be positive")
    if len({endpoint.operator_id for endpoint in args.rpc}) != len(args.rpc):
        parser.error("RPC operator identifiers must be distinct")

    observations: list[dict[str, Any]] = []
    errors: list[str] = []
    for endpoint in args.rpc:
        try:
            observations.append(observe(endpoint, args.object_id, args.package_id))
        except ObservationError as error:
            errors.append(str(error))

    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for observation in observations:
        groups.setdefault(agreement_key(observation), []).append(observation)
    agreeing = max(groups.values(), key=len, default=[])
    if len(agreeing) < args.required_agreement:
        raise ObservationError(
            f"insufficient independent RPC agreement: required "
            f"{args.required_agreement}, agreeing {len(agreeing)}; errors={errors}"
        )

    representative = agreeing[0]
    output = {
        "schema": "astra-pq-live-iota-observation-v1",
        "live_iota_claim": True,
        "agreement": {
            "required": args.required_agreement,
            "agreeing": len(agreeing),
            "operators": [item["operator_id"] for item in agreeing],
        },
        "anchor": {
            key: representative[key]
            for key in (
                "network_id",
                "package_id",
                "object_id",
                "object_version",
                "previous_transaction",
                "transaction_digest",
                "package_version",
                "epoch",
                "predecessor_hash",
                "checkpoint_hash",
                "activation_time",
                "bundle_uri",
                "governance_key_set_id",
            )
        },
        "observations": agreeing,
        "rejected_endpoint_errors": errors,
    }
    with open(args.output, "x", encoding="utf-8") as output_file:
        json.dump(output, output_file, indent=2, sort_keys=True)
        output_file.write("\n")
    json.dump(output, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ObservationError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
