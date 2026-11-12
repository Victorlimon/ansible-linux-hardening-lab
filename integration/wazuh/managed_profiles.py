"""Resolve and seal the fixed profiles accepted by managed hardening."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import json
from pathlib import Path
import re
from typing import Any


IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}\Z")
SUPPORTED_PLATFORMS = frozenset(("ubuntu24", "debian12"))
ALLOWED_PROTOCOLS = frozenset(("tcp", "udp"))
APPLY_DISPOSITIONS = frozenset(("automated", "gated_unsafe"))


class ProfileRejected(ValueError):
    """The supplied profile selection cannot enter managed execution."""


@dataclass(frozen=True)
class NetworkRule:
    service: str
    port: int
    protocol: str
    cidr: str


@dataclass(frozen=True)
class SealedProfile:
    release_id: str
    inventory_profile_id: str
    host_profile_id: str
    section_profile_id: str
    platform: str
    target_alias: str
    section: str
    tags: tuple[str, ...]
    gates: tuple[str, ...]
    disposition: str
    network_rules: tuple[NetworkRule, ...]
    digest: str


def load_profile_catalog(path: Path) -> dict[str, Any]:
    """Load a local JSON profile catalog without accepting duplicate keys."""
    try:
        raw = path.read_text(encoding="utf-8")
        value = json.loads(raw, object_pairs_hook=_unique_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProfileRejected("invalid profile catalog") from exc
    if type(value) is not dict:
        raise ProfileRejected("invalid profile catalog")
    return value


def resolve_profile(
    catalog: dict[str, Any],
    *,
    release_id: str,
    inventory_profile_id: str,
    host_profile_id: str,
    section_profile_id: str,
    target_alias: str,
) -> SealedProfile:
    """Resolve only catalog identifiers and return their immutable digest."""
    _ensure_keys(catalog, {"releases"}, "profile catalog")
    releases = _mapping(catalog["releases"], "releases")
    release = _lookup(releases, release_id, "release")
    _ensure_keys(release, {"inventory_profiles", "host_profiles", "section_profiles"}, "release")

    inventories = _mapping(release["inventory_profiles"], "inventory profiles")
    hosts = _mapping(release["host_profiles"], "host profiles")
    sections = _mapping(release["section_profiles"], "section profiles")
    inventory = _lookup(inventories, inventory_profile_id, "inventory profile")
    host = _lookup(hosts, host_profile_id, "host profile")
    section = _lookup(sections, section_profile_id, "section profile")

    _ensure_keys(inventory, {"platform", "aliases"}, "inventory profile")
    _ensure_keys(host, {"inventory_profile", "platform", "alias"}, "host profile")
    _ensure_keys(section, {
        "host_profile", "section", "tags", "gates", "disposition", "network_rules",
    }, "section profile")

    platform = _platform(inventory["platform"])
    aliases = _identifiers(inventory["aliases"], "inventory aliases", nonempty=True)
    if host["inventory_profile"] != inventory_profile_id:
        raise ProfileRejected("host profile does not match inventory profile")
    if _platform(host["platform"]) != platform:
        raise ProfileRejected("host platform does not match inventory profile")
    alias = _identifier(host["alias"], "host alias")
    if alias not in aliases:
        raise ProfileRejected("host alias is not allowed by inventory profile")
    if target_alias != alias:
        raise ProfileRejected("target alias does not match host profile")
    if section["host_profile"] != host_profile_id:
        raise ProfileRejected("section profile does not match host profile")

    section_name = _identifier(section["section"], "section")
    tags = _identifiers(section["tags"], "tags", nonempty=True)
    gates = _identifiers(section["gates"], "gates")
    disposition = section["disposition"]
    if type(disposition) is not str or disposition not in APPLY_DISPOSITIONS:
        raise ProfileRejected("section disposition is not eligible for managed apply")
    rules = _network_rules(section["network_rules"])

    contents = {
        "release_id": release_id,
        "inventory_profile_id": inventory_profile_id,
        "host_profile_id": host_profile_id,
        "section_profile_id": section_profile_id,
        "platform": platform,
        "target_alias": alias,
        "section": section_name,
        "tags": tags,
        "gates": gates,
        "disposition": disposition,
        "network_rules": [rule.__dict__ for rule in rules],
    }
    digest = hashlib.sha256(_canonical_bytes(contents)).hexdigest()
    return SealedProfile(
        release_id=release_id,
        inventory_profile_id=inventory_profile_id,
        host_profile_id=host_profile_id,
        section_profile_id=section_profile_id,
        platform=platform,
        target_alias=alias,
        section=section_name,
        tags=tags,
        gates=gates,
        disposition=disposition,
        network_rules=rules,
        digest=digest,
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProfileRejected("duplicate JSON key")
        result[key] = value
    return result


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise ProfileRejected(f"invalid {name}")
    return value


def _lookup(values: dict[str, Any], identifier: str, name: str) -> dict[str, Any]:
    if type(identifier) is not str or identifier not in values:
        raise ProfileRejected(f"unknown {name}")
    return _mapping(values[identifier], name)


def _ensure_keys(value: dict[str, Any], expected: set[str], name: str) -> None:
    if set(value) != expected:
        raise ProfileRejected(f"invalid {name} schema")


def _identifier(value: Any, name: str) -> str:
    if type(value) is not str or not IDENTIFIER.fullmatch(value):
        raise ProfileRejected(f"invalid {name}")
    return value


def _identifiers(value: Any, name: str, *, nonempty: bool = False) -> tuple[str, ...]:
    if type(value) is not list or (nonempty and not value):
        raise ProfileRejected(f"invalid {name}")
    result = tuple(_identifier(item, name) for item in value)
    if len(set(result)) != len(result):
        raise ProfileRejected(f"duplicate {name}")
    return result


def _platform(value: Any) -> str:
    if type(value) is not str or value not in SUPPORTED_PLATFORMS:
        raise ProfileRejected("unsupported platform")
    return value


def _network_rules(value: Any) -> tuple[NetworkRule, ...]:
    if type(value) is not list:
        raise ProfileRejected("invalid network rules")
    rules = []
    for item in value:
        item = _mapping(item, "network rule")
        _ensure_keys(item, {"service", "port", "protocol", "cidr"}, "network rule")
        service = _identifier(item["service"], "network service")
        port = item["port"]
        if type(port) is not int or not 1 <= port <= 65535:
            raise ProfileRejected("port must be 1..65535")
        protocol = item["protocol"]
        if type(protocol) is not str or protocol not in ALLOWED_PROTOCOLS:
            raise ProfileRejected("unsupported protocol")
        cidr = item["cidr"]
        try:
            network = ipaddress.ip_network(cidr, strict=True)
        except ValueError as exc:
            raise ProfileRejected("CIDR must be canonical") from exc
        if type(cidr) is not str or str(network) != cidr:
            raise ProfileRejected("CIDR must be canonical")
        if (service == "ssh" or port == 22) and network.prefixlen == 0:
            raise ProfileRejected("SSH CIDR /0 is forbidden")
        rules.append(NetworkRule(service=service, port=port, protocol=protocol, cidr=cidr))
    return tuple(rules)


def _canonical_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
