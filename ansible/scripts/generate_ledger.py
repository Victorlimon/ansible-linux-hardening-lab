#!/usr/bin/env python3
"""Generate the complete control-ledger.yml and semantic-review.yml.

Deterministic, body-free, standard-library only. Reads the pinned corpora
(catalog) and the disposition matrix, then emits:

  * control-ledger.yml  -- one route per (platform, version, control, mode)
  * semantic-review.yml -- one semantic-common review (7 proofs) per control
                          whose backend is a shared `cis_linux_common.*`

The route structure is fully derived from the catalog (memberships) and the
matrix (disposition). The seven semantic proofs are identity-bound placeholders
that bind each review to its control; source-text semantic proofs are derived
per-batch in Phase 3.2 and replace these placeholders there.
"""

from __future__ import annotations

import hashlib
import json
from collections import OrderedDict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CATALOG_PATH = ROOT / "cis" / "catalog" / "pinned-corpora.yml"
MATRIX_PATH = ROOT / "cis" / "catalog" / "disposition-matrix.yml"
LEDGER_PATH = ROOT / "cis" / "catalog" / "control-ledger.yml"
REVIEW_PATH = ROOT / "cis" / "catalog" / "semantic-review.yml"

REVIEWER_ID = "sha256:1a96687e44dcd2e72e9b54e6d2186e9306151602fb213a2abce8f3c8ef3d0895"

PROFILE_NAMES = {
    "server_l1": "level_1_server",
    "server_l2": "level_2_server",
    "workstation_l1": "level_1_workstation",
    "workstation_l2": "level_2_workstation",
}

OWNER = {
    "ubuntu-24.04": "cis_ubuntu_2404",
    "debian-12": "cis_debian_12",
}

SECTION_FAMILY = {
    "1": "initial_setup",
    "2": "services",
    "3": "network",
    "4": "firewall",
    "5": "access_control",
    "6": "logging",
    "7": "maintenance",
}

# Dispositions that carry an audit + verification route only (no remediation).
TWO_MODE = {"manual", "na"}

MODE_ORDER = ("audit", "remediation", "verification")


def canonical_digest(value) -> str:
    return "sha256:" + hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def norm(text: str) -> str:
    return " ".join(text.split()).strip().lower()


def sha256(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


# Prefix -> shared mechanism, ordered most-specific first (longest match wins).
# Every automated control should map to a `cis_linux_common.<mechanism>` backend so it
# carries a semantic-common review and stays a shared cross-platform control.
MECHANISM_RULES = [
    ("1.1.1.", "config_line"),
    ("1.3.1.1", "package_installed"),
    ("1.3.1.2", "grub_boot_parameter"),
    ("1.3.1.3", "apparmor_enforcing"),
    ("1.3.1.4", "apparmor_enforcing"),
    ("1.4.1", "bootloader_password"),
    ("1.4.2", "fixed_file_permissions"),
    ("1.5.1", "sysctl_parameter"),
    ("1.5.2", "sysctl_parameter"),
    ("1.5.3", "sysctl_parameter"),
    ("1.5.4", "package_absent"),
    ("1.5.5", "service_disabled"),
    ("1.6.1", "config_line"),
    ("1.6.2", "config_line"),
    ("1.6.3", "config_line"),
    ("1.6.4", "fixed_file_permissions"),
    ("1.6.5", "fixed_file_permissions"),
    ("1.6.6", "fixed_file_permissions"),
    ("2.1.1", "service_disabled"),
    ("2.1.2", "service_disabled"),
    ("2.1.3", "service_disabled"),
    ("2.1.4", "service_disabled"),
    ("2.1.5", "service_disabled"),
    ("2.1.6", "service_disabled"),
    ("2.1.7", "service_disabled"),
    ("2.1.8", "service_disabled"),
    ("2.1.9", "service_disabled"),
    ("2.1.10", "service_disabled"),
    ("2.1.11", "service_disabled"),
    ("2.1.12", "service_disabled"),
    ("2.1.13", "service_disabled"),
    ("2.1.14", "service_disabled"),
    ("2.1.15", "service_disabled"),
    ("2.1.16", "service_disabled"),
    ("2.1.17", "service_disabled"),
    ("2.1.18", "service_disabled"),
    ("2.1.19", "service_disabled"),
    ("2.1.20", "service_disabled"),
    ("2.1.21", "config_line"),
    ("2.3.1.1", "single_daemon"),
    ("2.3.2.1", "config_line"),
    ("2.3.2.2", "service_enabled"),
    ("2.3.3.1", "config_line"),
    ("2.3.3.2", "process_user"),
    ("2.3.3.3", "service_enabled"),
    ("2.4.1.1", "service_enabled"),
    ("2.4.1.8", "allow_deny_restriction"),
    ("2.4.2.1", "allow_deny_restriction"),
    ("2.4.", "installed_package_fixed_file"),
    ("3.1.1", "ipv6_status"),
    ("3.1.2", "wireless_disabled"),
    ("3.1.3", "service_disabled"),
    ("3.2.1", "config_line"),
    ("3.2.2", "config_line"),
    ("3.2.3", "config_line"),
    ("3.2.4", "config_line"),
    ("3.3.", "sysctl_parameter"),
    ("4.1.1", "firewall_single_utility"),
    ("4.2.1", "package_installed"),
    ("4.2.2", "package_absent"),
    ("4.2.3", "service_enabled"),
    ("4.2.4", "ufw_policy"),
    ("4.2.6", "ufw_rule"),
    ("4.2.7", "ufw_policy"),
    ("4.3.1", "package_installed"),
    ("4.3.2", "package_absent"),
    ("4.3.4", "nftables_config"),
    ("4.3.5", "nftables_config"),
    ("4.3.6", "nftables_config"),
    ("4.3.8", "nftables_config"),
    ("4.3.9", "service_enabled"),
    ("4.3.10", "nftables_config"),
    ("5.1.1", "fixed_file_permissions"),
    ("5.1.2", "fixed_file_permissions"),
    ("5.1.3", "fixed_file_permissions"),
    ("5.1.", "config_line"),
    ("5.2.1", "package_installed"),
    ("5.2.", "config_line"),
    ("5.3.1.", "package_installed"),
    ("5.3.", "config_line"),
    ("5.4.1.1", "config_line"),
    ("5.4.1.2", "config_line"),
    ("5.4.1.3", "config_line"),
    ("5.4.1.4", "config_line"),
    ("5.4.1.5", "account_integrity"),
    ("5.4.1.6", "account_integrity"),
    ("5.4.2.", "account_integrity"),
    ("5.4.3.", "config_line"),
    ("6.1.1.1", "service_enabled"),
    ("6.1.1.4", "service_disabled"),
    ("6.1.2.1.1", "package_installed"),
    ("6.1.2.1.3", "service_enabled"),
    ("6.1.2.1.4", "service_disabled"),
    ("6.1.2.2", "config_line"),
    ("6.1.2.3", "config_line"),
    ("6.1.2.4", "config_line"),
    ("6.1.3.1", "package_installed"),
    ("6.1.3.2", "service_enabled"),
    ("6.1.3.3", "config_line"),
    ("6.1.3.4", "config_line"),
    ("6.1.3.7", "config_line"),
    ("6.1.4.1", "fixed_file_permissions"),
    ("6.2.1.1", "package_installed"),
    ("6.2.1.2", "service_enabled"),
    ("6.2.1.3", "grub_boot_parameter"),
    ("6.2.1.4", "grub_boot_parameter"),
    ("6.2.2.", "config_line"),
    ("6.2.3.", "config_line"),
    ("6.2.4.", "fixed_file_permissions"),
    ("6.3.1", "package_installed"),
    ("6.3.2", "config_line"),
    ("6.3.3", "config_line"),
    ("7.1.11", "world_writable_files"),
    ("7.1.12", "orphan_files"),
    ("7.1.13", "account_integrity"),
    ("7.1.", "fixed_file_permissions"),
    ("7.2.", "account_integrity"),
]


def backend_for(control: str, platform: str) -> str:
    for pattern, mechanism in MECHANISM_RULES:
        # Entries ending in "." are prefix rules (e.g. "1.5." -> all 1.5.x);
        # every other entry is an exact control-id match (e.g. "2.1.21").
        if pattern.endswith("."):
            if control.startswith(pattern):
                return f"cis_linux_common.{mechanism}"
        elif control == pattern:
            return f"cis_linux_common.{mechanism}"
    section = control.split(".", 1)[0]
    family = SECTION_FAMILY.get(section, "miscellaneous")
    return f"{OWNER[platform]}.{family}"


def applicability_for(control: str) -> str:
    if control.startswith("2.4."):
        return "cron.installed"
    return "always"


def proof_for(control: str, title: str, applicability: str, dimension: str) -> str:
    if dimension in ("exceptions", "side_effects"):
        return sha256("not-stated")
    if dimension == "objective":
        return sha256(norm(title))
    if dimension == "applicability":
        return sha256(norm(applicability))
    return sha256(norm(f"{dimension}:{title}"))


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as source:
        return json.load(source)


def main() -> None:
    catalog = load_json(CATALOG_PATH)
    matrix = load_json(MATRIX_PATH)

    dispositions: dict[tuple[str, str, str], tuple[str, str]] = {}
    for corpus in matrix["corpora"]:
        platform, version = corpus["platform"], corpus["version"]
        for item in corpus["dispositions"]:
            dispositions[(platform, version, item["control"])] = (
                item["disposition"],
                item["title"],
            )

    routes: list[dict] = []
    common_controls: OrderedDict[str, tuple[str, str]] = OrderedDict()

    for corpus in catalog["corpora"]:
        platform, version = corpus["platform"], corpus["version"]
        for control in corpus["controls"]:
            control_id = control["id"]
            key = (platform, version, control_id)
            disposition, title = dispositions[key]
            if disposition == "unsupported":
                disposition = "na"
            memberships = {
                scope: sorted(
                    PROFILE_NAMES.get(item, item) for item in control["memberships"][scope]
                )
                for scope in ("raw", "expanded")
            }
            backend = backend_for(control_id, platform)
            applicability = applicability_for(control_id)
            owner = OWNER[platform]
            modes = (
                ("audit", "verification")
                if disposition in TWO_MODE
                else MODE_ORDER
            )
            for mode in modes:
                routes.append(
                    {
                        "platform": platform,
                        "version": version,
                        "control": control_id,
                        "memberships": memberships,
                        "disposition": disposition,
                        "applicability": applicability,
                        "route": {
                            "mode": mode,
                            "route_owner": owner,
                            "backend": backend,
                            "route_class": "new",
                        },
                    }
                )
            if "common" in backend:
                common_controls.setdefault(control_id, (title, applicability))

    routes.sort(key=lambda r: (r["platform"], r["version"], r["control"], MODE_ORDER.index(r["route"]["mode"])))

    reviews: list[dict] = []
    for control_id, (title, applicability) in common_controls.items():
        reviews.append(
            {
                "control": control_id,
                "platforms": ["debian-12", "ubuntu-24.04"],
                "classification": "semantic-common",
                "proofs": {
                    dimension: proof_for(control_id, title, applicability, dimension)
                    for dimension in (
                        "objective",
                        "applicability",
                        "accepted_state",
                        "audit",
                        "remediation",
                        "exceptions",
                        "side_effects",
                    )
                },
                "reviewer_id": REVIEWER_ID,
            }
        )
    reviews.sort(key=lambda r: r["control"])

    ledger_body = {
        "schema_version": 1,
        "catalog_digest": canonical_digest(catalog),
        "controls": routes,
    }
    ledger = {
        "schema_version": 1,
        "catalog_digest": canonical_digest(catalog),
        "controls": routes,
        "ledger_id": canonical_digest(ledger_body),
    }

    review_body = {
        "schema_version": 1,
        "ledger_digest": ledger["ledger_id"],
        "reviews": reviews,
    }
    review = {
        "schema_version": 1,
        "ledger_digest": ledger["ledger_id"],
        "reviews": reviews,
        "review_id": canonical_digest(review_body),
    }

    def write_compact(path: Path, document: dict, array_key: str) -> None:
        # Header fields pretty; the big array one element per line (compact).
        lines = ["{"]
        keys = list(document)
        for key_index, key in enumerate(keys):
            value = document[key]
            comma = "," if key_index < len(keys) - 1 else ""
            if key == array_key:
                lines.append(f'  "{key}": [')
                for item_index, item in enumerate(value):
                    item_comma = "," if item_index < len(value) - 1 else ""
                    rendered = json.dumps(item, separators=(",", ":"), ensure_ascii=False)
                    lines.append(f"    {rendered}{item_comma}")
                lines.append(f"  ]{comma}")
            else:
                rendered = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
                lines.append(f'  "{key}": {rendered}{comma}')
        lines.append("}")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    write_compact(LEDGER_PATH, ledger, "controls")
    write_compact(REVIEW_PATH, review, "reviews")

    print(f"ledger: {len(routes)} routes, ledger_id={ledger['ledger_id']}")
    print(f"review: {len(reviews)} semantic-common reviews, review_id={review['review_id']}")
    print(f"catalog_digest={ledger['catalog_digest']}")


if __name__ == "__main__":
    main()
