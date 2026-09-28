#!/usr/bin/env python3
"""Qualify deterministic CIS metadata using standard-library Python."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import defaultdict
from pathlib import Path, PurePath
from typing import Any, NoReturn


class RoutingError(Exception):
    """A bounded routing qualification failure."""

    def __init__(self, invariant: str):
        super().__init__(invariant)
        self.invariant = invariant


def fail(invariant: str) -> NoReturn:
    raise RoutingError(invariant)


def require(condition: bool, invariant: str = "ROUTING_INPUT_INVALID") -> None:
    if not condition:
        fail(invariant)


def nonempty_string(value: Any) -> str:
    require(isinstance(value, str) and bool(value) and len(value) <= 256)
    return value


def resolve_input(root: Path, argument: str, directory: bool = False) -> Path:
    relative = PurePath(argument)
    require(not relative.is_absolute() and ".." not in relative.parts)
    candidate = (root / relative).resolve(strict=True)
    require(candidate.is_relative_to(root) and (candidate.is_dir() if directory else candidate.is_file()))
    return candidate


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as source:
        return json.load(source)


SCHEMA_FILES = {
    "control-ledger.schema.json": ("urn:cis:control-ledger:v1", "ledger_id", "6220458c990248bc0740cb42d2246688290bf64dabb2968f9f60a3c0bae87627"),
    "qualification-receipt.schema.json": ("urn:cis:qualification-receipt:v1", "receipt_id", "e52edd0e3188910f2bd5fd4becbe9e48df816d9ff5c4236d7f9e1415f13e4cfc"),
    "qualification-request.schema.json": ("urn:cis:qualification-request:v1", "request_id", "64f99449f7c285719053f30128256cd8e586563b2491e03b1b8d610cf53316d3"),
    "semantic-review.schema.json": ("urn:cis:semantic-review:v1", "review_id", "379068ce95f737fbcd181e1647aa9ee34f059cff83ebb03a51666c9f979053fe"),
}
FORBIDDEN_KEYS = {"title", "body", "recommendation", "prose", "private", "secret"}
JSON_TYPES = {"object": dict, "array": list, "string": str, "integer": int}
SEMANTIC_DIMENSIONS = {
    "objective", "applicability", "accepted_state", "audit", "remediation",
    "exceptions", "side_effects",
}
PROFILE_NAMES = {
    "server_l1": "level_1_server",
    "server_l2": "level_2_server",
    "workstation_l1": "level_1_workstation",
    "workstation_l2": "level_2_workstation",
}
AUTHORIZED_PILOT_TARGET = {
    ("debian-12", "1.1.0", "2.4.1.2"),
    ("ubuntu-24.04", "1.0.0", "2.4.1.2"),
}


def canonical_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def validate_value(value: Any, schema: dict[str, Any]) -> None:
    expected_type = schema.get("type")
    if expected_type:
        require(type(value) is JSON_TYPES[expected_type], "SCHEMA_DOCUMENT_INVALID")
    require("const" not in schema or value == schema["const"], "SCHEMA_DOCUMENT_INVALID")
    require("enum" not in schema or value in schema["enum"], "SCHEMA_DOCUMENT_INVALID")
    require("minimum" not in schema or value >= schema["minimum"], "SCHEMA_DOCUMENT_INVALID")
    if isinstance(value, str) and "pattern" in schema:
        if not re.fullmatch(schema["pattern"], value):
            fail("SCHEMA_HASH_INVALID" if "sha256" in schema["pattern"] else "SCHEMA_DOCUMENT_INVALID")
    if isinstance(value, list):
        require(len(value) >= schema.get("minItems", 0), "SCHEMA_DOCUMENT_INVALID")
        require(not schema.get("uniqueItems") or len({json.dumps(item, sort_keys=True) for item in value}) == len(value), "SCHEMA_DOCUMENT_INVALID")
        for item in value:
            validate_value(item, schema.get("items", {}))
    if isinstance(value, dict):
        required = schema.get("required", [])
        require(all(key in value for key in required), "SCHEMA_DOCUMENT_INVALID")
        properties = schema.get("properties", {})
        require(schema.get("additionalProperties") is not False or set(value).issubset(properties), "SCHEMA_DOCUMENT_INVALID")
        for key, child in value.items():
            if key in properties:
                validate_value(child, properties[key])


def validate_privacy(value: Any) -> None:
    if isinstance(value, dict):
        if FORBIDDEN_KEYS.intersection(key.lower() for key in value):
            fail("SCHEMA_PRIVACY_VIOLATION")
        for child in value.values():
            validate_privacy(child)
    elif isinstance(value, list):
        for child in value:
            validate_privacy(child)
    elif isinstance(value, str) and (value.startswith(("/", "~/", "$", "${")) or re.match(r"^[A-Za-z]:[\\/]", value)):
        fail("SCHEMA_PATH_INVALID")


def qualify_schema_contracts(root: Path, schemas_arg: str, documents_arg: str) -> int:
    schema_root = resolve_input(root, schemas_arg, directory=True)
    document_root = resolve_input(root, documents_arg, directory=True)
    require({path.name for path in schema_root.glob("*.json")} == set(SCHEMA_FILES), "SCHEMA_DRIFT")
    require({path.name for path in document_root.glob("*.json")} == set(SCHEMA_FILES), "SCHEMA_DOCUMENT_INVALID")
    documents: dict[str, Any] = {}
    for name, (schema_id, identity_field, schema_digest) in sorted(SCHEMA_FILES.items()):
        schema = load_json(schema_root / name)
        require(schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema", "SCHEMA_DRIFT")
        require(schema.get("$id") == schema_id, "SCHEMA_IDENTITY_DUPLICATE")
        require(hashlib.sha256((schema_root / name).read_bytes()).hexdigest() == schema_digest, "SCHEMA_DRIFT")
        document = load_json(document_root / name)
        validate_privacy(document)
        validate_value(document, schema)
        unsigned = {key: value for key, value in document.items() if key != identity_field}
        identity_invariant = "SCHEMA_RECEIPT_OVERWRITE" if name == "qualification-receipt.schema.json" else "SCHEMA_IDENTITY_MISMATCH"
        require(document.get(identity_field) == canonical_digest(unsigned), identity_invariant)
        documents[name] = document
    ledger = documents["control-ledger.schema.json"]
    route_keys: set[tuple[str, ...]] = set()
    for control in ledger["controls"]:
        route = control["route"]
        key = (control["platform"], control["version"], control["control"], route["mode"])
        require(key not in route_keys, "SCHEMA_ROUTE_DUPLICATE")
        route_keys.add(key)
        require(control["disposition"] != "unsupported" or not control["memberships"]["expanded"], "SCHEMA_UNSUPPORTED_SELECTED")
    require(documents["semantic-review.schema.json"]["ledger_digest"] == ledger["ledger_id"], "SCHEMA_IDENTITY_MISMATCH")
    request = documents["qualification-request.schema.json"]
    receipt = documents["qualification-receipt.schema.json"]
    require(request["schema_digest"] == "sha256:" + SCHEMA_FILES["qualification-request.schema.json"][2], "SCHEMA_IDENTITY_MISMATCH")
    require(request["catalog_digest"] == ledger["catalog_digest"] and request["ledger_digest"] == ledger["ledger_id"], "SCHEMA_IDENTITY_MISMATCH")
    require(request["semantic_review_digest"] == documents["semantic-review.schema.json"]["review_id"], "SCHEMA_IDENTITY_MISMATCH")
    require(receipt["schema_digest"] == "sha256:" + SCHEMA_FILES["qualification-receipt.schema.json"][2], "SCHEMA_IDENTITY_MISMATCH")
    for field in ("catalog_digest", "ledger_digest", "semantic_review_digest", "candidate_digest"):
        require(receipt[field] == request[field], "SCHEMA_IDENTITY_MISMATCH")
    require(receipt["request_digest"] == request["request_id"], "SCHEMA_IDENTITY_MISMATCH")
    profile = receipt["profile_identity"]
    require(all(profile[field] == request[field] for field in ("platform", "version", "profile", "membership_scope")), "SCHEMA_IDENTITY_MISMATCH")
    aggregate = receipt["aggregate"]
    disposition_total = sum(aggregate[field] for field in ("automated", "manual", "na", "gated_unsafe", "unsupported"))
    require(aggregate["selected"] == disposition_total == aggregate["passed"] + aggregate["failed"], "SCHEMA_AGGREGATE_INCOHERENT")
    require((aggregate["status"] == "qualified") == (aggregate["failed"] == aggregate["unsupported"] == 0), "SCHEMA_AGGREGATE_INCOHERENT")
    print("SCHEMA_CONTRACTS_VALID schemas=4 documents=4")
    return 0
def normalize_catalog(value: Any) -> set[tuple[str, str, str]]:
    require(isinstance(value, dict))
    if value.get("schema_version") == 2:
        corpora = value.get("corpora")
        require(isinstance(corpora, list) and bool(corpora))
    else:
        corpora = [value]

    expected: set[tuple[str, str, str]] = set()
    for corpus in corpora:
        require(isinstance(corpus, dict))
        platform = nonempty_string(corpus.get("platform"))
        version = nonempty_string(corpus.get("version"))
        controls = corpus.get("controls")
        require(isinstance(controls, list) and bool(controls))
        for control in controls:
            require(isinstance(control, dict))
            control_id = nonempty_string(control.get("id"))
            key = (platform, version, control_id)
            require(key not in expected)
            expected.add(key)
    return expected


def normalize_routes(
    value: Any,
) -> dict[tuple[str, str, str], list[tuple[str, str]]]:
    require(isinstance(value, dict) and value.get("schema_version") == 1)
    routes = value.get("controls")
    require(isinstance(routes, list))
    grouped: dict[tuple[str, str, str], list[tuple[str, str]]] = defaultdict(list)
    for route in routes:
        require(isinstance(route, dict))
        key = (
            nonempty_string(route.get("platform")),
            nonempty_string(route.get("version")),
            nonempty_string(route.get("control")),
        )
        owner = nonempty_string(route.get("route").get("route_owner"))
        route_class = nonempty_string(route.get("route").get("route_class"))
        require(route_class in {"legacy", "new"})
        grouped[key].append((owner, route_class))
    return grouped


def qualify_routes(catalog: Any, ledger: Any) -> int:
    expected = normalize_catalog(catalog)
    grouped = normalize_routes(ledger)
    require(set(grouped).issubset(expected))

    for key in sorted(grouped):
        classes = {route_class for _, route_class in grouped[key]}
        if "legacy" in classes and "new" in classes:
            fail("ROUTING_LEGACY_NEW_CONFLICT")

    for key in sorted(grouped):
        owners = {owner for owner, _ in grouped[key]}
        if len(owners) != 1:
            fail("ROUTING_DUPLICATE_OWNER")

    if any(key not in grouped for key in sorted(expected)):
        fail("ROUTING_OWNER_MISSING")

    print(f"ROUTING_VALID corpora={len({key[:2] for key in expected})} routes={len(expected)}")
    return 0


def catalog_controls(
    value: Any, platform: str, version: str,
) -> dict[str, dict[str, list[str]]]:
    require(isinstance(value, dict), "PRODUCTION_DOCUMENT_INVALID")
    corpora = value.get("corpora") if value.get("schema_version") == 2 else [value]
    require(isinstance(corpora, list), "PRODUCTION_DOCUMENT_INVALID")
    selected = [
        corpus for corpus in corpora
        if isinstance(corpus, dict)
        and (corpus.get("platform"), corpus.get("version")) == (platform, version)
    ]
    require(len(selected) == 1, "PRODUCTION_CATALOG_IDENTITY_INVALID")
    controls = selected[0].get("controls")
    require(isinstance(controls, list) and controls, "PRODUCTION_DOCUMENT_INVALID")
    result: dict[str, dict[str, list[str]]] = {}
    for control in controls:
        require(isinstance(control, dict), "PRODUCTION_DOCUMENT_INVALID")
        control_id = nonempty_string(control.get("id"))
        require(control_id not in result, "PRODUCTION_CATALOG_DUPLICATE")
        memberships = control.get("memberships")
        require(isinstance(memberships, dict), "PRODUCTION_DOCUMENT_INVALID")
        normalized: dict[str, list[str]] = {}
        for scope in ("raw", "expanded"):
            values = memberships.get(scope)
            require(isinstance(values, list), "PRODUCTION_DOCUMENT_INVALID")
            normalized[scope] = sorted(PROFILE_NAMES.get(item, item) for item in values)
        result[control_id] = normalized
    return result


def normalize_coverage(
    request: dict[str, Any], catalog: Any,
) -> tuple[str, tuple[tuple[str, str, str], ...]]:
    mode = request.get("coverage_mode", "exhaustive")
    raw_target = request.get("coverage_target")
    if mode == "exhaustive":
        require(raw_target is None, "PRODUCTION_COVERAGE_INVALID")
        controls = catalog_controls(catalog, request["platform"], request["version"])
        profile = request["profile"]
        scope = request["membership_scope"]
        target = tuple(sorted(
            (request["platform"], request["version"], control)
            for control, memberships in controls.items()
            if profile in memberships[scope]
        ))
        require(bool(target), "PRODUCTION_COVERAGE_INVALID")
        return mode, target

    require(mode == "pilot" and isinstance(raw_target, list) and raw_target, "PRODUCTION_COVERAGE_INVALID")
    target: list[tuple[str, str, str]] = []
    for item in raw_target:
        require(isinstance(item, dict) and set(item) == {"platform", "version", "control"}, "PRODUCTION_COVERAGE_INVALID")
        target.append(tuple(nonempty_string(item[field]) for field in ("platform", "version", "control")))
    normalized = tuple(target)
    require(normalized == tuple(sorted(normalized)), "PRODUCTION_COVERAGE_INVALID")
    require(len(set(normalized)) == len(normalized), "PRODUCTION_COVERAGE_INVALID")
    require(set(normalized).issubset(AUTHORIZED_PILOT_TARGET), "PRODUCTION_COVERAGE_INVALID")
    return mode, normalized


def require_exact_coverage(
    target: tuple[tuple[str, str, str], ...],
    ledger_entries: list[dict[str, Any]], reviews: list[dict[str, Any]],
) -> None:
    expected = set(target)
    ledger_projection = {
        (entry.get("platform"), entry.get("version"), entry.get("control"))
        for entry in ledger_entries
    }
    require(ledger_projection == expected, "PRODUCTION_COVERAGE_MISMATCH")

    versions: dict[tuple[str, str], str] = {}
    for platform, version, control in target:
        key = (platform, control)
        require(key not in versions, "PRODUCTION_COVERAGE_MISMATCH")
        versions[key] = version
    review_projection: list[tuple[str, str, str]] = []
    for item in reviews:
        for platform in item.get("platforms", []):
            key = (platform, item.get("control"))
            require(key in versions, "PRODUCTION_COVERAGE_MISMATCH")
            review_projection.append((platform, versions[key], key[1]))
    require(len(review_projection) == len(set(review_projection)), "PRODUCTION_COVERAGE_MISMATCH")
    require(set(review_projection) == expected, "PRODUCTION_COVERAGE_MISMATCH")


def validate_receipt_scope(
    request: dict[str, Any], receipt: dict[str, Any], mode: str,
    target: tuple[tuple[str, str, str], ...],
) -> None:
    expected_target = [
        {"platform": platform, "version": version, "control": control}
        for platform, version, control in target
    ]
    profile = {field: request[field] for field in ("platform", "version", "profile", "membership_scope")}
    require(receipt.get("request_digest") == request.get("request_id"), "PRODUCTION_RECEIPT_SCOPE_MISMATCH")
    require(receipt.get("profile_identity") == profile, "PRODUCTION_RECEIPT_SCOPE_MISMATCH")
    require(receipt.get("coverage_mode") == mode, "PRODUCTION_RECEIPT_SCOPE_MISMATCH")
    require(receipt.get("coverage_target") == expected_target, "PRODUCTION_RECEIPT_SCOPE_MISMATCH")


def expected_owner(platform: str) -> str:
    if platform == "ubuntu-24.04":
        return "cis_ubuntu_2404"
    if platform == "debian-12":
        return "cis_debian_12"
    return "fixture_adapter"


def qualify_production_documents(
    root: Path, catalog_arg: str, ledger_arg: str, review_arg: str,
    schemas_arg: str, platform: str, version: str,
    request_arg: str | None = None, receipt_arg: str | None = None,
) -> int:
    catalog = load_json(resolve_input(root, catalog_arg))
    ledger = load_json(resolve_input(root, ledger_arg))
    review = load_json(resolve_input(root, review_arg))
    schema_root = resolve_input(root, schemas_arg, directory=True)
    validate_privacy(ledger)
    validate_privacy(review)
    validate_value(ledger, load_json(schema_root / "control-ledger.schema.json"))
    validate_value(review, load_json(schema_root / "semantic-review.schema.json"))

    expected = catalog_controls(catalog, platform, version)
    coverage_target = tuple((platform, version, control) for control in sorted(expected))
    if request_arg is not None or receipt_arg is not None:
        require(request_arg is not None and receipt_arg is not None, "PRODUCTION_DOCUMENT_INVALID")
        request = load_json(resolve_input(root, request_arg))
        receipt = load_json(resolve_input(root, receipt_arg))
        validate_privacy(request)
        validate_privacy(receipt)
        validate_value(request, load_json(schema_root / "qualification-request.schema.json"))
        validate_value(receipt, load_json(schema_root / "qualification-receipt.schema.json"))
        require((request["platform"], request["version"]) == (platform, version), "PRODUCTION_COVERAGE_INVALID")
        coverage_mode, coverage_target = normalize_coverage(request, catalog)
        require(request["request_id"] == canonical_digest({key: value for key, value in request.items() if key != "request_id"}), "PRODUCTION_IDENTITY_MISMATCH")
        require(receipt["receipt_id"] == canonical_digest({key: value for key, value in receipt.items() if key != "receipt_id"}), "PRODUCTION_IDENTITY_MISMATCH")
        require(request["schema_digest"] == "sha256:" + SCHEMA_FILES["qualification-request.schema.json"][2], "PRODUCTION_IDENTITY_MISMATCH")
        require(receipt["schema_digest"] == "sha256:" + SCHEMA_FILES["qualification-receipt.schema.json"][2], "PRODUCTION_IDENTITY_MISMATCH")
        require(request["catalog_digest"] == canonical_digest(catalog), "PRODUCTION_IDENTITY_MISMATCH")
        require(request["ledger_digest"] == ledger["ledger_id"] and request["semantic_review_digest"] == review["review_id"], "PRODUCTION_IDENTITY_MISMATCH")
        require(all(receipt[field] == request[field] for field in ("catalog_digest", "ledger_digest", "semantic_review_digest", "candidate_digest")), "PRODUCTION_IDENTITY_MISMATCH")
        validate_receipt_scope(request, receipt, coverage_mode, coverage_target)
        require_exact_coverage(coverage_target, ledger["controls"], review["reviews"])
    target_controls = {
        (target_platform, target_version, control): catalog_controls(
            catalog, target_platform, target_version,
        )[control]
        for target_platform, target_version, control in coverage_target
    }
    require(ledger["ledger_id"] == canonical_digest({key: value for key, value in ledger.items() if key != "ledger_id"}), "PRODUCTION_IDENTITY_MISMATCH")
    require(review["review_id"] == canonical_digest({key: value for key, value in review.items() if key != "review_id"}), "PRODUCTION_IDENTITY_MISMATCH")
    require(ledger["catalog_digest"] == canonical_digest(catalog), "PRODUCTION_IDENTITY_MISMATCH")
    require(review["ledger_digest"] == ledger["ledger_id"], "PRODUCTION_IDENTITY_MISMATCH")

    routes: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    selected: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for entry in ledger["controls"]:
        route = entry["route"]
        key = (entry["platform"], entry["version"], entry["control"], route["mode"])
        routes[key].append(entry)
        if key[:3] in target_controls:
            selected[key[:3]].append(entry)

    for entries in routes.values():
        classes = {entry["route"]["route_class"] for entry in entries}
        require(not {"legacy", "new"}.issubset(classes), "PRODUCTION_LEGACY_NEW_CONFLICT")
        require(len(entries) == 1, "PRODUCTION_ROUTE_DUPLICATE")
    require(set(selected) == set(target_controls), "PRODUCTION_CONTROL_OMITTED")

    reviews: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in review["reviews"]:
        require(set(item["proofs"]) == SEMANTIC_DIMENSIONS, "PRODUCTION_SEMANTIC_DIMENSIONS_INVALID")
        reviews[item["control"]].append(item)

    for target_key, entries in selected.items():
        target_platform, _, control_id = target_key
        owner = expected_owner(target_platform)
        dispositions = {entry["disposition"] for entry in entries}
        require(len(dispositions) == 1, "PRODUCTION_DISPOSITION_AMBIGUOUS")
        disposition = next(iter(dispositions))
        require(disposition != "unsupported", "PRODUCTION_UNSUPPORTED_SELECTED")
        modes = {entry["route"]["mode"] for entry in entries}
        required_modes = {"audit", "verification"} if disposition in {"manual", "na"} else {"audit", "remediation", "verification"}
        require(modes == required_modes, "PRODUCTION_MANUAL_ROUTE_INVALID" if disposition == "manual" else "PRODUCTION_ROUTE_MODES_INVALID")
        for entry in entries:
            actual_memberships = {scope: sorted(entry["memberships"][scope]) for scope in ("raw", "expanded")}
            require(actual_memberships == target_controls[target_key], "PRODUCTION_MEMBERSHIP_MISMATCH")
            route = entry["route"]
            require(route["route_owner"] == owner, "PRODUCTION_ROUTE_OWNER_INVALID")
            require(route["backend"] != route["route_owner"], "PRODUCTION_ROUTE_BACKEND_INVALID")
            if "common" in route["backend"]:
                proven = any(
                    item["classification"] == "semantic-common"
                    and target_platform in item["platforms"]
                    for item in reviews.get(control_id, [])
                )
                require(proven, "PRODUCTION_SEMANTIC_COMMON_UNPROVEN")

    print(f"PRODUCTION_DOCUMENTS_VALID platform={platform} version={version} controls={len(target_controls)} routes={sum(len(items) for items in selected.values())}")
    return 0


def run() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--catalog")
    parser.add_argument("--ledger")
    parser.add_argument("--schemas")
    parser.add_argument("--documents")
    parser.add_argument("--semantic-review")
    parser.add_argument("--request")
    parser.add_argument("--receipt")
    parser.add_argument("--platform")
    parser.add_argument("--version")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--routing-only", action="store_true")
    mode.add_argument("--schema-contracts", action="store_true")
    mode.add_argument("--production-documents", action="store_true")
    arguments = parser.parse_args()

    root = Path(arguments.root).expanduser().resolve(strict=True)
    require(root.is_dir())
    if arguments.schema_contracts:
        require(arguments.schemas is not None and arguments.documents is not None)
        return qualify_schema_contracts(root, arguments.schemas, arguments.documents)
    if arguments.production_documents:
        require(all((arguments.catalog, arguments.ledger, arguments.semantic_review, arguments.schemas, arguments.platform, arguments.version)), "PRODUCTION_DOCUMENT_INVALID")
        return qualify_production_documents(
            root, arguments.catalog, arguments.ledger, arguments.semantic_review,
            arguments.schemas, arguments.platform, arguments.version,
            arguments.request, arguments.receipt,
        )
    require(arguments.catalog is not None and arguments.ledger is not None)
    return qualify_routes(
        load_json(resolve_input(root, arguments.catalog)),
        load_json(resolve_input(root, arguments.ledger)),
    )


def main() -> int:
    try:
        return run()
    except RoutingError as error:
        print(f"ERROR invariant={error.invariant}", file=sys.stderr)
    except Exception:
        print("ERROR invariant=ROUTING_INPUT_INVALID", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
