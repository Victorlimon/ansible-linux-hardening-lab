#!/usr/bin/env python3
"""Validate a body-free CIS catalog using only the Python standard library."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path, PurePath
from typing import Any, NoReturn


class CatalogError(Exception):
    """A bounded catalog validation failure."""

    def __init__(self, invariant: str):
        super().__init__(invariant)
        self.invariant = invariant


def fail(invariant: str) -> NoReturn:
    raise CatalogError(invariant)


def require(condition: bool, invariant: str = "CATALOG_SCHEMA_INVALID") -> None:
    if not condition:
        fail(invariant)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            if key == "platform":
                fail("CATALOG_DUPLICATE_PLATFORM")
            if key == "version":
                fail("CATALOG_DUPLICATE_VERSION")
            fail("CATALOG_DUPLICATE_PROFILE" if key.startswith("level_") else "CATALOG_SCHEMA_INVALID")
        result[key] = value
    return result


def exact_fields(value: Any, fields: set[str]) -> dict[str, Any]:
    require(isinstance(value, dict) and set(value) == fields)
    return value


def nonempty_string(value: Any) -> str:
    require(isinstance(value, str) and bool(value) and len(value) <= 256)
    return value


def string_list(value: Any) -> list[str]:
    require(isinstance(value, list) and all(isinstance(item, str) and item for item in value))
    require(len(value) == len(set(value)))
    return value


def reject_forbidden_fields(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = key.lower().replace("-", "_")
            if "title" in normalized:
                fail("CATALOG_FORBIDDEN_TITLE")
            if "body" in normalized:
                fail("CATALOG_FORBIDDEN_BODY")
            if "recommend" in normalized:
                fail("CATALOG_FORBIDDEN_RECOMMENDATION")
            reject_forbidden_fields(child)
    elif isinstance(value, list):
        for child in value:
            reject_forbidden_fields(child)


def validate_source_identity(catalog: dict[str, Any]) -> str:
    if "source_identity" not in catalog:
        fail("CATALOG_SOURCE_IDENTITY_MISSING")
    source = catalog["source_identity"]
    if not isinstance(source, dict):
        fail("CATALOG_SOURCE_IDENTITY_AMBIGUOUS")
    exact_fields(source, {"document_id", "edition", "fingerprint"})
    nonempty_string(source["document_id"])
    nonempty_string(source["edition"])
    fingerprint = nonempty_string(source["fingerprint"])
    require(bool(re.fullmatch(r"sha256:[0-9a-f]{64}", fingerprint)))
    return fingerprint


def validate_profiles(value: Any) -> dict[str, dict[str, Any]]:
    require(isinstance(value, dict) and bool(value))
    profiles: dict[str, dict[str, Any]] = {}
    for name, profile_value in value.items():
        nonempty_string(name)
        profile = exact_fields(
            profile_value, {"raw", "expanded", "raw_count", "expanded_count"}
        )
        raw = string_list(profile["raw"])
        expanded = string_list(profile["expanded"])
        require(set(raw).issubset(expanded))
        for field in ("raw_count", "expanded_count"):
            require(type(profile[field]) is int and profile[field] >= 0)
        profiles[name] = profile
    return profiles


def validate_controls(
    value: Any, profile_names: set[str], source_fingerprint: str
) -> tuple[dict[str, dict[str, Any]], dict[str, set[str]], dict[str, set[str]]]:
    require(isinstance(value, list) and bool(value))
    controls: dict[str, dict[str, Any]] = {}
    raw_by_profile = {name: set() for name in profile_names}
    expanded_by_profile = {name: set() for name in profile_names}
    for control_value in value:
        control = exact_fields(
            control_value, {"id", "status", "source_fingerprint", "memberships"}
        )
        control_id = nonempty_string(control["id"])
        if control_id in controls:
            fail("CATALOG_DUPLICATE_CONTROL")
        require(control["status"] == "selected")
        require(control["source_fingerprint"] == source_fingerprint)
        memberships = exact_fields(control["memberships"], {"raw", "expanded"})
        raw = string_list(memberships["raw"])
        expanded = string_list(memberships["expanded"])
        require(set(expanded).issubset(profile_names))
        controls[control_id] = control
        for name in raw:
            raw_by_profile[name].add(control_id)
        for name in expanded:
            expanded_by_profile[name].add(control_id)
    return controls, raw_by_profile, expanded_by_profile


def validate_single_catalog(value: Any) -> dict[str, Any]:
    require(isinstance(value, dict))
    reject_forbidden_fields(value)
    source_fingerprint = validate_source_identity(value)
    exact_fields(
        value,
        {
            "schema_version",
            "generator",
            "source_identity",
            "platform",
            "version",
            "profiles",
            "controls",
        },
    )
    require(value["schema_version"] == 1)
    generator = exact_fields(value["generator"], {"name", "version"})
    nonempty_string(generator["name"])
    nonempty_string(generator["version"])
    nonempty_string(value["platform"])
    nonempty_string(value["version"])

    profiles = validate_profiles(value["profiles"])
    controls, raw_by_profile, expanded_by_profile = validate_controls(
        value["controls"], set(profiles), source_fingerprint
    )
    control_ids = set(controls)
    selected_ids = set().union(*(set(profile["expanded"]) for profile in profiles.values()))
    if not selected_ids.issubset(control_ids):
        fail("CATALOG_SELECTED_CONTROL_MISSING")
    if control_ids != selected_ids:
        fail("CATALOG_SILENT_OMISSION")

    for name, profile in profiles.items():
        if set(profile["raw"]) != raw_by_profile[name]:
            fail("CATALOG_RAW_MEMBERSHIP_MISMATCH")
        if set(profile["expanded"]) != expanded_by_profile[name]:
            fail("CATALOG_EXPANDED_MEMBERSHIP_MISMATCH")
        if profile["raw_count"] != len(profile["raw"]):
            fail("CATALOG_RAW_DENOMINATOR_MISMATCH")
        if profile["expanded_count"] != len(profile["expanded"]):
            fail("CATALOG_EXPANDED_DENOMINATOR_MISMATCH")
    return value


def validate_catalog(value: Any) -> dict[str, Any]:
    require(isinstance(value, dict))
    if value.get("schema_version") != 2 and "corpora" not in value:
        return validate_single_catalog(value)

    reject_forbidden_fields(value)
    exact_fields(value, {"schema_version", "corpora"})
    require(value["schema_version"] == 2)
    corpora = value["corpora"]
    require(isinstance(corpora, list), "CATALOG_SCHEMA_INVALID")
    require(bool(corpora), "CATALOG_CONTAINER_EMPTY")

    identities: set[tuple[str, str]] = set()
    validated: list[dict[str, Any]] = []
    for corpus in corpora:
        if not isinstance(corpus, dict):
            fail("CATALOG_SCHEMA_INVALID")
        platform = corpus.get("platform")
        version = corpus.get("version")
        if (
            not isinstance(platform, str)
            or not platform
            or not isinstance(version, str)
            or not version
        ):
            fail("CATALOG_CORPUS_IDENTITY_AMBIGUOUS")
        validated_corpus = validate_single_catalog(corpus)
        identity = (platform, version)
        if identity in identities:
            fail("CATALOG_DUPLICATE_CORPUS")
        identities.add(identity)
        validated.append(validated_corpus)

    value["corpora"] = sorted(
        validated, key=lambda corpus: (corpus["platform"], corpus["version"])
    )
    return value


def resolve_catalog(root_argument: str, catalog_argument: str) -> Path:
    root = Path(root_argument).expanduser().resolve(strict=True)
    require(root.is_dir(), "CATALOG_PATH_INVALID")
    catalog_path = PurePath(catalog_argument)
    if catalog_path.is_absolute():
        fail("CATALOG_PATH_ABSOLUTE")
    if ".." in catalog_path.parts:
        fail("CATALOG_PATH_TRAVERSAL")
    candidate = (root / catalog_path).resolve(strict=True)
    if not candidate.is_relative_to(root):
        fail("CATALOG_PATH_SYMLINK_ESCAPE")
    require(candidate.is_file(), "CATALOG_PATH_INVALID")
    return candidate


def run() -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--root", required=True)
    parser.add_argument("--catalog", required=True)
    arguments = parser.parse_args()
    catalog_path = resolve_catalog(arguments.root, arguments.catalog)
    with catalog_path.open("r", encoding="utf-8") as catalog_file:
        value = json.load(catalog_file, object_pairs_hook=reject_duplicate_keys)
    catalog = validate_catalog(value)
    sys.stdout.write(json.dumps(catalog, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


def main() -> int:
    try:
        return run()
    except CatalogError as error:
        print(f"ERROR invariant={error.invariant}", file=sys.stderr)
    except Exception:
        print("ERROR invariant=CATALOG_INPUT_INVALID", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
