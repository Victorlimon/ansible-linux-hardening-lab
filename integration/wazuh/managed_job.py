#!/usr/bin/python3 -I
"""Root-installed, manually triggered Wazuh to Ansible job gateway.

This is a source artifact. It is inert until an administrator installs it at
ENTRYPOINT and creates a trusted policy and inventory on the control node.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from contextlib import contextmanager
from enum import Enum
from typing import NamedTuple


# Imports from a sealed release must never create bytecode inside its payload.
sys.dont_write_bytecode = True


ENTRYPOINT = Path("/var/ossec/active-response/bin/ansible-job")
POLICY_PATH = Path("/etc/ansible-wazuh/jobs.json")
DEPLOYMENT_LOCK = Path("/etc/ansible-wazuh/deployment.lock")
RELEASES_ROOT = Path("/opt/ansible-hardening/releases")
ACTIVATION_DIR = Path("/var/lib/ansible-wazuh/activated-releases")
APPROVAL_DIR = Path("/var/lib/ansible-wazuh/approvals")
STATE_DIR = Path("/var/lib/ansible-wazuh/state")
LOCAL_TEMP = Path("/var/lib/ansible-wazuh/runtime-tmp")
EVENT_LOG = Path("/var/log/ansible-wazuh-jobs.jsonl")
MAX_REQUEST = 65536
# A full-selection check with --diff over ~260 controls exceeds 1 MiB of output.
MAX_OUTPUT = 8 * 1024 * 1024
# Root-read evidence files (logs, policy, approvals) share the output bound.
MAX_TRUSTED_FILE = MAX_OUTPUT
TIMEOUT = 3600
# --list-tasks parses every role task file; one core needs ~75-100 s per call
# for a single tag, so the previous 120 s bound rejected full selections.
LIST_TASKS_TIMEOUT = 600
INVENTORY_TIMEOUT = 180
ID = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}\Z")
CONTROL_TAG = re.compile(r"cis_[0-9]+(?:_[0-9]+){2,6}\Z")
SECTION = re.compile(r"[1-7](?:\.[1-9][0-9]?)?\Z")
SECTION_IMPORT = re.compile(
    r"\Asections/section_0([1-7])_[^/]+/[^/]+/(audit|remediation|verification)\.yml\Z"
)
JOBS = {
    "debian_preflight": ("debian12", "cis_debian_12_preflight.yml", "preflight"),
    "ubuntu_audit": ("ubuntu24", "audit/cis_ubuntu_2404.yml", "audit"),
    "debian_audit": ("debian12", "audit/cis_debian_12.yml", "audit"),
    "ubuntu_verify": ("ubuntu24", "verify/cis_ubuntu_2404.yml", "verify"),
    "debian_verify": ("debian12", "verify/cis_debian_12.yml", "verify"),
    "ubuntu_hardening": ("ubuntu24", "hardening/cis_ubuntu_2404.yml", "hardening"),
    "debian_hardening": ("debian12", "hardening/cis_debian_12.yml", "hardening"),
}
GATES = {
    "ubuntu24": ("cis_ubuntu_2404_remediation_enabled=true",),
    "debian12": ("cis_debian_12_remediation_enabled=true",
                 "cis_debian_12_canary_confirmed=true"),
}
REMEDIATION_CONTROLS = {
    "ubuntu24": {"cron_hourly": "cis_2_4_1_3", "cron_daily": "cis_2_4_1_4"},
    "debian12": {"cron_hourly": "cis_2_4_1_3", "cron_daily": "cis_2_4_1_4"},
}
PLUGIN_TYPES = ("ACTION", "BECOME", "CACHE", "CALLBACK", "CLICONF", "CONNECTION", "DOC_FRAGMENT",
                "FILTER", "HTTPAPI", "INVENTORY", "LOOKUP", "NETCONF", "SHELL",
                "STRATEGY", "TERMINAL", "TEST", "VARS")
PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
BOOTSTRAP_SHA256 = "5a3913bb182725a314383a13381425bd70899bed80704f432216e691d6db3f02"
LEGACY_LAB_V3_BOOTSTRAP_SHA256 = "84ac988521df48c7a22fffbcd69d5b3fb82288d5f411d4506a2cfb843ff6b45c"
LEGACY_LAB_V14_BOOTSTRAP_SHA256 = "ebe1836f9501dadabe2959a669cedde5e162a396eeb2665b5ead8352c3d35853"


def canonical_launcher(bootstrap: Path, command: str) -> bytes:
    if command not in ("playbook", "inventory"):
        raise Reject("unknown sealed launcher")
    return ("#!/bin/sh\nexec /usr/bin/python3 -I -S -B " + str(bootstrap)
            + " " + command + " \"$@\"\n").encode("ascii")


def legacy_lab_v14_launcher(bootstrap: Path, command: str) -> bytes:
    if command not in ("playbook", "inventory"):
        raise Reject("unknown sealed launcher")
    return ("#!/bin/sh\nexec /usr/bin/python3 -I -S " + str(bootstrap)
            + " " + command + " \"$@\"\n").encode("ascii")


class Reject(ValueError):
    """A request must not launch Ansible."""


class RequestKind(Enum):
    LEGACY_CHECK = "legacy-check"
    MANAGED_CHECK = "managed-check-v1"
    MANAGED_APPLY = "managed-apply-v1"
    MANAGED_V2 = "managed-v2"


class LegacyCheckRequest(NamedTuple):
    job_id: str
    target_id: str
    control_id: str
    approval_slot: str

    @property
    def kind(self) -> RequestKind:
        return RequestKind.LEGACY_CHECK


class ManagedCheckRequest(NamedTuple):
    request_id: str
    release_id: str
    inventory_profile_id: str
    host_profile_id: str
    section_profile_id: str
    target_alias: str
    change_id: str

    @property
    def kind(self) -> RequestKind:
        return RequestKind.MANAGED_CHECK


class ManagedApplyRequest(NamedTuple):
    request_id: str
    release_id: str
    inventory_profile_id: str
    host_profile_id: str
    section_profile_id: str
    target_alias: str
    change_id: str
    approval_id: str

    @property
    def kind(self) -> RequestKind:
        return RequestKind.MANAGED_APPLY


class ManagedV2Request(NamedTuple):
    mode: str
    request_id: str
    change_id: str
    release_id: str
    playbook_id: str
    inventory_profile_id: str
    targets: tuple[str, ...]
    selection_kind: str
    selection_names: tuple[str, ...]
    extra_vars: dict
    approvals: dict

    @property
    def kind(self) -> RequestKind:
        return RequestKind.MANAGED_V2


WazuhRequest = LegacyCheckRequest | ManagedCheckRequest | ManagedApplyRequest | ManagedV2Request


def _network(value: str, *, ssh: bool = False) -> str:
    if type(value) is not str:
        raise Reject("invalid CIDR")
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise Reject("invalid CIDR") from exc
    if network.version != 4 or str(network) != value or (ssh and network.prefixlen == 0):
        raise Reject("unapproved CIDR")
    return value


def _managed_vars(value: object, playbook_id: str) -> dict:
    if type(value) is not dict:
        raise Reject("invalid extra_vars")
    if not value:
        return {}
    if playbook_id != "ubuntu_hardening" or set(value) - {
            "cis_ufw_ssh_port", "cis_ufw_ssh_allowed_sources", "cis_ufw_allowed_in_rules"}:
        raise Reject("unapproved extra_vars")
    result = {}
    for key, item in value.items():
        if key == "cis_ufw_ssh_port":
            if type(item) is not int or not 1 <= item <= 65535:
                raise Reject("invalid SSH port")
            result[key] = item
        elif key == "cis_ufw_ssh_allowed_sources":
            if type(item) is not list or not item or len(item) > 16:
                raise Reject("invalid SSH sources")
            result[key] = [_network(source, ssh=True) for source in item]
        else:
            if type(item) is not list or len(item) > 32:
                raise Reject("invalid inbound rules")
            rules = []
            for rule in item:
                if type(rule) is not dict or set(rule) != {"from_ip", "port", "proto"}:
                    raise Reject("invalid inbound rule")
                port = rule["port"]
                if type(port) is not int or not 1 <= port <= 65535 or port == value.get("cis_ufw_ssh_port", 22):
                    raise Reject("invalid inbound port")
                if rule["proto"] not in ("tcp", "udp"):
                    raise Reject("invalid inbound protocol")
                origin = rule["from_ip"]
                # The current root policy has no explicit public-source grant.
                _network(origin)
                rules.append({"from_ip": origin, "port": port, "proto": rule["proto"]})
            result[key] = rules
    return result


def parse_managed_v2(raw: str) -> ManagedV2Request:
    if type(raw) is not str or len(raw.encode("utf-8")) > 8192:
        raise Reject("managed order too large")
    try:
        data = json.loads(raw, object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise Reject("invalid managed order") from exc
    if raw != json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True):
        raise Reject("managed order must be canonical JSON")
    mandatory = {"mode", "request_id", "change_id", "release_id", "playbook_id",
                 "inventory_profile_id", "targets", "selection", "extra_vars"}
    if type(data) is not dict or set(data) not in (mandatory, mandatory | {"approvals"}):
        raise Reject("invalid managed order schema")
    mode = data["mode"]
    if mode not in ("check", "apply") or ("approvals" in data) != (mode == "apply"):
        raise Reject("invalid managed order mode")
    request_id = canonical_uuid(data["request_id"])
    change_id = managed_identifier(data["change_id"])
    release_id = managed_identifier(data["release_id"])
    playbook_id = managed_identifier(data["playbook_id"])
    if playbook_id not in ("ubuntu_hardening", "debian_hardening", "ubuntu_audit",
                           "debian_audit", "ubuntu_verify", "debian_verify"):
        raise Reject("unapproved playbook")
    if mode == "apply" and JOBS[playbook_id][2] != "hardening":
        raise Reject("only hardening playbooks accept apply")
    inventory_profile_id = managed_identifier(data["inventory_profile_id"])
    targets = data["targets"]
    if type(targets) is not list or not 1 <= len(targets) <= 16:
        raise Reject("invalid targets")
    targets = tuple(managed_identifier(value) for value in targets)
    if len(set(targets)) != len(targets) or any(value in ("all", "ungrouped") for value in targets):
        raise Reject("duplicate or broad targets")
    selection = data["selection"]
    if type(selection) is not dict or set(selection) != {"kind", "names"}:
        raise Reject("invalid selection")
    kind, names = selection["kind"], selection["names"]
    if kind not in ("full", "tags", "roles", "sections") or type(names) is not list:
        raise Reject("invalid selection")
    names = tuple(item if kind == "sections" and type(item) is str and SECTION.fullmatch(item)
                  else managed_identifier(item) for item in names)
    if (kind == "full") != (len(names) == 0) or len(names) > 32 or len(set(names)) != len(names):
        raise Reject("invalid selection names")
    if kind == "sections" and any(not SECTION.fullmatch(item) for item in names):
        raise Reject("invalid section")
    if any(item in ("always", "never", "all", "tagged", "untagged") for item in names):
        raise Reject("special tag forbidden")
    extra_vars = _managed_vars(data["extra_vars"], playbook_id)
    approvals = data.get("approvals", {})
    if type(approvals) is not dict or any(type(key) is not str for key in approvals):
        raise Reject("invalid approvals")
    approvals = {managed_identifier(key): canonical_uuid(value) for key, value in approvals.items()}
    return ManagedV2Request(mode, request_id, change_id, release_id, playbook_id,
                            inventory_profile_id, targets, kind, names, extra_vars, approvals)


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise Reject("duplicate JSON key")
        value[key] = item
    return value


def identifier(value: str) -> str:
    if type(value) is not str or not ID.fullmatch(value):
        raise Reject("invalid identifier")
    return value


def canonical_uuid(value: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError, TypeError) as exc:
        raise Reject("invalid UUID identifier") from exc
    if str(parsed) != value or parsed.int == 0:
        raise Reject("invalid UUID identifier")
    return value


def managed_identifier(value: str) -> str:
    value = identifier(value)
    # Digests are derived from root-local evidence, never supplied by Wazuh.
    if re.fullmatch(r"[0-9A-Fa-f]{64}", value):
        raise Reject("digest is not an identifier")
    return value


def parse_wazuh(line: bytes) -> WazuhRequest:
    if len(line) > MAX_REQUEST or not line.endswith(b"\n"):
        raise Reject("invalid request framing")
    try:
        message = json.loads(line.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Reject("invalid JSON") from exc
    if (type(message) is not dict or type(message.get("version")) is not int
            or message["version"] != 1 or message.get("command") != "add"
            or type(message.get("origin")) is not dict
            or message["origin"].get("module") != "wazuh-execd"
            or type(message.get("parameters")) is not dict):
        raise Reject("invalid Wazuh protocol")
    args = message["parameters"].get("extra_args")
    if type(args) is not list or not args or any(type(item) is not str for item in args):
        raise Reject("expected identifier strings")
    if args[0] == RequestKind.MANAGED_V2.value:
        if len(args) != 2:
            raise Reject("invalid managed-v2 argument count")
        return parse_managed_v2(args[1])
    if args[0] in (RequestKind.MANAGED_CHECK.value, RequestKind.MANAGED_APPLY.value):
        is_apply = args[0] == RequestKind.MANAGED_APPLY.value
        if len(args) != (9 if is_apply else 8):
            raise Reject("invalid managed argument count")
        request_id = canonical_uuid(args[1])
        identifiers = tuple(managed_identifier(item) for item in args[2:8])
        if identifiers[4] in ("all", "ungrouped"):
            raise Reject("group target not allowed")
        if is_apply:
            return ManagedApplyRequest(request_id, *identifiers, canonical_uuid(args[8]))
        return ManagedCheckRequest(request_id, *identifiers)
    if len(args) != 4:
        raise Reject("expected four legacy identifiers")
    job, target, control = (identifier(item) for item in args[:3])
    approval = args[3]
    if type(approval) is not str:
        raise Reject("invalid approval identifier")
    if job not in JOBS:
        raise Reject("unknown job")
    if target in ("all", "ungrouped") or control in ("all", "ungrouped"):
        raise Reject("group or broad control not allowed")
    if approval != "none":
        try:
            if str(uuid.UUID(approval)) != approval:
                raise ValueError
        except ValueError as exc:
            raise Reject("invalid approval identifier") from exc
    return LegacyCheckRequest(job, target, control, approval)


def dispatch_request(request: WazuhRequest) -> int:
    """Dispatch by validated contract, never by an approval-looking string."""
    if type(request) is LegacyCheckRequest:
        # The legacy fourth slot is compatibility data, not apply authority.
        return run_job(request.job_id, request.target_id, request.control_id, "none")
    if type(request) is ManagedCheckRequest:
        return run_managed_check(request)
    if type(request) is ManagedApplyRequest:
        raise Reject("managed apply disabled: coordinator unavailable")
    if type(request) is ManagedV2Request:
        return run_managed_v2(request)
    raise Reject("unknown request type")


def load_managed_catalog(policy: dict) -> dict:
    """Import only reviewed helper bytes inside the active sealed release."""
    managed = RELEASES_ROOT / policy["release_id"] / "payload" / "managed"
    trusted_tree_digest(managed)
    module_path = managed / "integration" / "wazuh" / "managed_profiles.py"
    trusted_file(module_path)
    import sys as _sys
    _sys.path.insert(0, str(managed))
    try:
        spec = importlib.util.spec_from_file_location("integration.wazuh.managed_profiles",
                                                   module_path)
        if spec is None or spec.loader is None:
            raise Reject("sealed profile resolver unavailable")
        module = importlib.util.module_from_spec(spec)
        _sys.modules[spec.name] = module
        spec.loader.exec_module(module)
    except (ImportError, OSError) as exc:
        raise Reject("sealed profile resolver unavailable") from exc
    raw = trusted_file(managed / "profiles.json")
    try:
        catalog = json.loads(raw, object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise Reject("invalid sealed profile catalog") from exc
    if type(catalog) is not dict or set(catalog) != {"releases"}:
        raise Reject("invalid sealed profile catalog")
    return catalog


def resolve_managed_profile(catalog: dict, request: ManagedCheckRequest):
    from integration.wazuh import managed_profiles
    return managed_profiles.resolve_profile(
        catalog, release_id=request.release_id,
        inventory_profile_id=request.inventory_profile_id,
        host_profile_id=request.host_profile_id,
        section_profile_id=request.section_profile_id,
        target_alias=request.target_alias)


def load_managed_supervisor(policy: dict):
    managed = RELEASES_ROOT / policy["release_id"] / "payload" / "managed"
    trusted_tree_digest(managed)
    module_path = managed / "integration" / "wazuh" / "managed_supervisor.py"
    trusted_file(module_path)
    sys.path.insert(0, str(managed))
    spec = importlib.util.spec_from_file_location("integration.wazuh.managed_supervisor",
                                               module_path)
    if spec is None or spec.loader is None:
        raise Reject("sealed supervisor unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except (ImportError, OSError) as exc:
        raise Reject("sealed supervisor unavailable") from exc
    return module


def _exclusive_record(path: Path, record: dict) -> None:
    payload = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise Reject("incomplete managed evidence")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    sync_directory(path.parent)


def _managed_check_record(path: Path) -> dict:
    try:
        value = json.loads(trusted_file(path), object_pairs_hook=unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise Reject("managed check evidence unavailable") from exc
    if type(value) is not dict or value.get("version") != 1:
        raise Reject("managed check evidence invalid")
    return value


def issue_managed_approval(request_id: str, issuer: str, reason: str,
                           ttl: int = 900) -> str:
    """Root's separate manual decision copies identity from completed evidence."""
    canonical_uuid(request_id)
    if type(ttl) is not int or not 1 <= ttl <= 3600:
        raise Reject("invalid approval TTL")
    with deployment_lock():
        policy, fingerprint = policy_and_hash()
        private_directory(STATE_DIR)
        evidence = _managed_check_record(STATE_DIR / (request_id + ".check.json"))
        diff = trusted_file(STATE_DIR / (request_id + ".managed-check.log"))
        if (evidence.get("request_id") != request_id
                or evidence.get("release_id") != policy["release_id"]
                or evidence.get("release_digest") != fingerprint
                or evidence.get("diff_digest") != hashlib.sha256(diff).hexdigest()):
            raise Reject("managed check evidence changed")
        supervisor = load_managed_supervisor(policy)
        current = int(time.time())
        approval = supervisor.create_approval(
            request_id=request_id, release_id=evidence["release_id"],
            release_digest=evidence["release_digest"],
            profile_digest=evidence["profile_digest"],
            inventory_profile_id=evidence["inventory_profile_id"],
            host_profile_id=evidence["host_profile_id"],
            section_profile_id=evidence["section_profile_id"],
            target_alias=evidence["target_alias"], section=evidence["section"],
            change_id=evidence["change_id"], diff_digest=evidence["diff_digest"],
            issuer=issuer, reason=reason, issued_at=current,
            expires_at=current + ttl)
        supervisor.issue(approval)
        return approval.approval_id


def run_managed_check(request: ManagedCheckRequest) -> int:
    """Produce one immutable root-owned check/diff for a fixed cron profile."""
    with deployment_lock():
        policy, fingerprint = policy_and_hash()
        if request.release_id != policy["release_id"]:
            raise Reject("inactive managed release")
        catalog = load_managed_catalog(policy)
        profile = resolve_managed_profile(catalog, request)
        expected_tag = REMEDIATION_CONTROLS.get(profile.platform, {}).get(profile.section)
        gate_names = tuple(item.removesuffix("=true") for item in GATES[profile.platform])
        if (profile.section not in ("cron_hourly", "cron_daily")
                or profile.tags != (expected_tag,) or expected_tag is None
                or profile.gates != gate_names or profile.network_rules
                or profile.disposition != "automated"
                or profile.target_alias != request.target_alias):
            raise Reject("managed profile is outside reviewed cron binding")
        targets = [key for key, item in policy["targets"].items()
                   if item == {"host": request.target_alias, "os": profile.platform}]
        if len(targets) != 1:
            raise Reject("managed target not in active policy")
        job_id = "ubuntu_hardening" if profile.platform == "ubuntu24" else "debian_hardening"
        host, playbook, tag, extras = selection(policy, job_id, targets[0], profile.section)
        if (host != request.target_alias or tag != expected_tag
                or tuple(item.removesuffix("=true") for item in extras) != gate_names):
            raise Reject("managed policy and catalog disagree")
        private_directory(STATE_DIR)
        evidence_path = STATE_DIR / (request.request_id + ".check.json")
        output = STATE_DIR / (request.request_id + ".managed-check.log")
        identity = {"request_id": request.request_id, "change_id": request.change_id,
                    "release_id": request.release_id,
                    "inventory_profile_id": request.inventory_profile_id,
                    "host_profile_id": request.host_profile_id,
                    "section_profile_id": request.section_profile_id,
                    "target_alias": request.target_alias}
        if evidence_path.exists():
            existing = _managed_check_record(evidence_path)
            if (all(existing.get(key) == value for key, value in identity.items())
                    and existing.get("release_digest") == fingerprint
                    and hashlib.sha256(trusted_file(output)).hexdigest() == existing.get("diff_digest")):
                return 0
            raise Reject("managed check request collision")
        if output.exists():
            raise Reject("incomplete managed check blocks replay")
        inventory = inventory_groups(policy, str(uuid.uuid4()))
        unique_target_addresses(policy, inventory)
        required_group = "ubuntu" if profile.platform == "ubuntu24" else "debian_12"
        if host in inventory or not group_contains(inventory, required_group, host):
            raise Reject("managed target absent from required inventory group")
        args = [str(Path(policy["ansible_bin_dir"]) / "ansible-playbook"),
                str(Path(policy["ansible_root"]) / "playbooks" / playbook),
                "-i", policy["inventory"], "--limit", host, "--tags", tag]
        for item in extras:
            args += ["-e", item]
        args += ["--check", "--diff"]
        emit("accepted", request.request_id, job_id, targets[0], profile.section,
             "managed-check", change_id=request.change_id)
        code, truncated = run_private(args, Path(policy["ansible_root"]),
                                      policy["service_user"], output)
        if code != 0 or truncated:
            emit("failed", request.request_id, job_id, targets[0], profile.section,
                 "managed-check", change_id=request.change_id)
            return 1
        diff = output.read_bytes()
        if len(diff) > MAX_OUTPUT:
            raise Reject("managed check output exceeds bound")
        record = {"version": 1, **identity, "platform": profile.platform,
                  "section": profile.section, "job_id": job_id,
                  "release_digest": fingerprint,
                  "profile_digest": hashlib.sha256((fingerprint + profile.digest).encode("ascii")).hexdigest(),
                  "diff_digest": hashlib.sha256(diff).hexdigest()}
        _exclusive_record(evidence_path, record)
        emit("completed", request.request_id, job_id, targets[0], profile.section,
             "managed-check", change_id=request.change_id)
        return 0


def _v2_path(request_id: str, host: str, suffix: str) -> Path:
    return STATE_DIR / (canonical_uuid(request_id) + "." + managed_identifier(host) + ".v2." + suffix)


def _task_blocks(source: str) -> list[str]:
    """Split the top-level tasks in the sealed adapter, without parsing Ansible YAML."""
    return [block for block in re.split(r"(?m)^(?=- )", source) if block.startswith("- ")]


def _task_tags(block: str) -> tuple[str, ...]:
    if block.startswith("- {"):
        match = re.search(r"\btags: \[([^\]\n]*)\]", block)
        if match is None:
            return ()
        return tuple(item.strip(" '\"\t") for item in match.group(1).split(",") if item.strip())
    match = re.search(r"(?m)^  tags:([^\n]*)", block)
    if match is None:
        return ()
    inline = match.group(1).strip()
    if inline.startswith("[") and inline.endswith("]"):
        return tuple(item.strip(" '\"\t") for item in inline[1:-1].split(",") if item.strip())
    if inline:
        return (inline.strip(" '\""),)
    tags = []
    for line in block[match.end():].splitlines():
        if not line.strip():
            continue
        item = re.fullmatch(r"    - ([A-Za-z0-9_.-]+)", line)
        if item is None:
            break
        tags.append(item.group(1))
    return tuple(tags)


def _import_path(block: str) -> str | None:
    if block.startswith("- {"):
        match = re.search(r"\bansible\.builtin\.import_tasks: ([^,\s}]+)", block)
    elif block.startswith("- ansible.builtin.import_tasks:"):
        match = re.search(r"(?m)^- ansible\.builtin\.import_tasks: ([^\s]+)$", block)
    else:
        match = re.search(r"(?m)^  ansible\.builtin\.import_tasks: ([^\s]+)$", block)
    return match.group(1) if match else None


def _section_tags(role_text: str, role_tasks: Path, sections: tuple[str, ...],
                  mode: str) -> tuple[str, ...]:
    """Expand sections to the actual control tags in the sealed adapter."""
    selected = set(sections)
    covered = set()
    tags = set()
    for block in _task_blocks(role_text):
        imported = _import_path(block)
        match = SECTION_IMPORT.fullmatch(imported) if imported else None
        if match is None or match.group(1) not in {item[0] for item in selected} or match.group(2) != mode:
            continue
        section = match.group(1)
        prefix = re.compile(r"cis_" + section + r"_(?:[0-9]+_)*[0-9]+\Z")
        candidates = [tag for tag in _task_tags(block) if prefix.fullmatch(tag)]
        if candidates:
            candidates = [max(candidates, key=lambda tag: (tag.count("_"), len(tag)))]
        else:
            # A few Ubuntu adapters put the control tag on their imported task.
            nested = trusted_file(role_tasks / imported).decode("utf-8")
            nested_blocks = _task_blocks(nested)
            if not nested_blocks:
                raise Reject("section contains an untagged adapter")
            for task in nested_blocks:
                child_tags = [tag for tag in _task_tags(task) if prefix.fullmatch(tag)]
                if not child_tags:
                    raise Reject("section contains an untagged adapter")
                candidates.append(max(child_tags, key=lambda tag: (tag.count("_"), len(tag))))
        for tag in candidates:
            for scope in selected:
                if tag.startswith("cis_" + scope.replace(".", "_") + "_"):
                    covered.add(scope)
                    tags.add(tag)
    if covered != selected or not tags:
        raise Reject("section has no reviewed tasks")
    return tuple(sorted(tags))


def _control_tag_present(role_text: str, role_tasks: Path, tag: str,
                         mode: str) -> bool:
    control = tag[4:].replace("_", ".")
    action = {"remediation": "Remediate", "audit": "Audit",
              "verification": "Verify"}[mode]
    name = re.compile(r"(?m)^- (?:\{name: ['\"]?|name: )" + action +
                      r" .* CIS " + re.escape(control) + r"(?:\s|['\"],|$)")
    for block in _task_blocks(role_text):
        if name.search(block) and tag in _task_tags(block):
            return True
        imported = _import_path(block)
        match = SECTION_IMPORT.fullmatch(imported) if imported else None
        if match is None or match.group(2) != mode or _task_tags(block):
            continue
        nested = trusted_file(role_tasks / imported).decode("utf-8")
        if any(name.search(task) and tag in _task_tags(task) for task in _task_blocks(nested)):
            return True
    return False


def _v2_plan(policy: dict, fingerprint: str, request: ManagedV2Request,
             inventory: dict) -> tuple[tuple[str, ...], dict]:
    if request.release_id != policy["release_id"]:
        raise Reject("inactive managed release")
    platform, playbook, kind = JOBS[request.playbook_id]
    catalog = load_managed_catalog(policy)
    try:
        profile = catalog["releases"][request.release_id]["inventory_profiles"][request.inventory_profile_id]
    except (KeyError, TypeError) as exc:
        raise Reject("unknown sealed inventory profile") from exc
    if type(profile) is not dict or set(profile) != {"platform", "aliases"} or profile["platform"] != platform:
        raise Reject("invalid sealed inventory profile")
    allowed = profile["aliases"]
    if type(allowed) is not list or not allowed or any(type(x) is not str for x in allowed):
        raise Reject("invalid sealed inventory aliases")
    configured = {value["host"] for value in policy["targets"].values() if value["os"] == platform}
    if not set(allowed) <= configured:
        raise Reject("sealed inventory exceeds active policy")
    selected = set()
    for target in request.targets:
        if target in allowed:
            selected.add(target)
        elif target in inventory:
            members = {host for host in allowed if group_contains(inventory, target, host)}
            # A group may not silently bring an unapproved host into scope.
            all_hosts = _group_hosts(inventory, target)
            if not members or all_hosts != members:
                raise Reject("inventory group exceeds sealed profile")
            selected.update(members)
        else:
            raise Reject("unknown target or group")
    if not selected or len(selected) > 16:
        raise Reject("invalid target expansion")
    required_group = ("ubuntu_2404" if request.playbook_id == "ubuntu_verify" else
                      "ubuntu" if platform == "ubuntu24" else "debian_12")
    if any(not group_contains(inventory, required_group, host) for host in selected):
        raise Reject("target outside playbook group")
    if request.mode == "apply" and set(request.approvals) != selected:
        raise Reject("one approval required for each host")
    if request.mode == "check" and request.approvals:
        raise Reject("check cannot carry approvals")
    role = "cis_ubuntu_2404" if platform == "ubuntu24" else "cis_debian_12"
    role_tasks = Path(policy["ansible_root"]) / "roles" / role / "tasks"
    role_text = trusted_file(role_tasks / "main.yml").decode("utf-8")
    role_selector = (role + "_remediation" if kind == "hardening" else
                     role + "_audit" if kind == "audit" else role + "_verification")
    if request.selection_kind == "full":
        tags = (role_selector,)
    elif request.selection_kind == "roles":
        if request.selection_names != (role,):
            raise Reject("role selector is not the installed hardening role")
        tags = (role_selector,)
    elif request.selection_kind == "sections":
        if kind == "preflight":
            raise Reject("preflight has no CIS sections")
        task_mode = {"hardening": "remediation", "audit": "audit", "verify": "verification"}[kind]
        tags = _section_tags(role_text, role_tasks, request.selection_names, task_mode)
    else:
        tags = request.selection_names
        task_mode = {"hardening": "remediation", "audit": "audit", "verify": "verification"}.get(kind)
        if task_mode is None:
            raise Reject("preflight has no CIS controls")
        for tag in tags:
            if not CONTROL_TAG.fullmatch(tag):
                raise Reject("unapproved control tag")
            if not _control_tag_present(role_text, role_tasks, tag, task_mode):
                raise Reject("tag has no reviewed task in installed role")
    if request.extra_vars and (platform != "ubuntu24" or
                               request.selection_kind in ("tags", "sections") and
                               not any(tag.startswith("cis_4_") for tag in tags)):
        raise Reject("extra_vars have no selected firewall consumer")
    identity = {"request_id": request.request_id, "change_id": request.change_id,
                "release_id": request.release_id, "release_digest": fingerprint,
                "playbook_id": request.playbook_id,
                "inventory_profile_id": request.inventory_profile_id,
                "hosts": sorted(selected), "selection": {"kind": request.selection_kind,
                "names": list(request.selection_names)}, "tags": list(tags),
                "extra_vars": request.extra_vars}
    identity["scope_digest"] = hashlib.sha256(json.dumps(identity, sort_keys=True,
                                                separators=(",", ":")).encode("ascii")).hexdigest()
    return tuple(sorted(selected)), identity


def _group_hosts(inventory: dict, group: str, seen: set[str] | None = None) -> set[str]:
    seen = set() if seen is None else seen
    if group in seen:
        raise Reject("inventory group cycle")
    seen.add(group)
    value = inventory.get(group)
    if type(value) is not dict or type(value.get("hosts", [])) is not list or type(value.get("children", [])) is not list:
        raise Reject("invalid inventory group")
    hosts = set(value.get("hosts", []))
    for child in value.get("children", []):
        if type(child) is not str:
            raise Reject("invalid inventory child")
        hosts.update(_group_hosts(inventory, child, seen.copy()))
    return hosts


def _v2_args(policy: dict, request: ManagedV2Request, host: str, plan: dict,
             vars_file: Path | None) -> list[str]:
    playbook = JOBS[request.playbook_id][1]
    args = [str(Path(policy["ansible_bin_dir"]) / "ansible-playbook"),
            str(Path(policy["ansible_root"]) / "playbooks" / playbook),
            "-i", policy["inventory"], "--limit", host,
            "--tags", ",".join(plan["tags"])]
    if JOBS[request.playbook_id][2] == "hardening":
        for gate in GATES[JOBS[request.playbook_id][0]]:
            args.extend(("-e", gate))
    if vars_file is not None:
        args.extend(("--extra-vars", "@" + str(vars_file)))
    if request.mode == "check" and JOBS[request.playbook_id][2] == "hardening":
        args.extend(("--check", "--diff"))
    return args


def _v2_selected_tasks(policy: dict, request: ManagedV2Request, host: str,
                       plan: dict, vars_file: Path | None) -> str:
    """Ask the sealed Ansible runtime which tasks the exact selector reaches."""
    command = _v2_args(policy, request, host, plan, vars_file)
    command = [item for item in command if item not in ("--check", "--diff")]
    command.append("--list-tasks")
    output = STATE_DIR / (str(uuid.uuid4()) + ".selected-tasks.log")
    try:
        code, truncated = run_private(command, Path(policy["ansible_root"]),
                                      policy["service_user"], output, timeout=LIST_TASKS_TIMEOUT)
        if code != 0 or truncated:
            raise Reject("sealed Ansible task listing failed")
        raw = trusted_file(output).decode("utf-8", errors="replace")
        lines = re.findall(r"(?m)^\s+(.+?)\s+TAGS:\s*\[([^\]\n]+)\]", raw)
        selected = []
        for name, tags in lines:
            tag_set = {tag.strip() for tag in tags.split(",")}
            if "preflight" not in name.lower() and tag_set.intersection(plan["tags"]):
                selected.append((name.strip(), tuple(sorted(tag_set))))
        if not selected or any(not any(tag in tags for _, tags in selected)
                               for tag in plan["tags"]):
            raise Reject("selection has no effective Ansible tasks")
        return hashlib.sha256(json.dumps(selected, sort_keys=True,
                                        separators=(",", ":")).encode("utf-8")).hexdigest()
    finally:
        output.unlink(missing_ok=True)


def _v2_preflight_tasks(policy: dict, request: ManagedV2Request,
                        host: str, plan: dict) -> str:
    vars_file = _v2_vars_file(policy, request, host)
    try:
        return _v2_selected_tasks(policy, request, host, plan, vars_file)
    finally:
        if vars_file is not None:
            vars_file.unlink(missing_ok=True)


def _v2_vars_file(policy: dict, request: ManagedV2Request, host: str) -> Path | None:
    if not request.extra_vars:
        return None
    account = pwd.getpwnam(policy["service_user"])
    service_directory(LOCAL_TEMP, account.pw_uid)
    path = LOCAL_TEMP / (request.request_id + "." + host + ".vars.json")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    try:
        os.fchown(fd, account.pw_uid, account.pw_gid)
        os.write(fd, json.dumps(request.extra_vars, sort_keys=True, separators=(",", ":")).encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)
    return path


def _v2_event(status: str, request: ManagedV2Request, host: str, plan: dict,
              *, recap: str | None = None, task_count: int | None = None,
              verification: str | None = None) -> None:
    value = {"timestamp": datetime.now(timezone.utc).isoformat(),
             "source": "ansible-wazuh-job", "status": status,
             "request_id": request.request_id, "change_id": request.change_id,
             "job_id": request.playbook_id, "target_id": host,
             "inventory_profile_id": request.inventory_profile_id,
             "selection": request.selection_kind, "scope_digest": plan["scope_digest"],
             "mode": request.mode}
    if recap is not None:
        value["recap"] = recap
    if task_count is not None:
        value["task_count"] = task_count
    if verification is not None:
        value["verification"] = verification
    fd = os.open(EVENT_LOG, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        metadata = os.fstat(fd)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
                or metadata.st_mode & 0o077 or metadata.st_nlink != 1):
            raise Reject("private event log required")
        os.write(fd, (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)


def _v2_recap(output: Path, host: str) -> tuple[str, bool, int]:
    raw = trusted_file(output).decode("utf-8", errors="replace")
    task_count = len(re.findall(r"(?m)^TASK \[", raw))
    # Do not forward arbitrary Ansible lines; only bounded numeric recap fields.
    match = re.search(r"(?m)^" + re.escape(host) +
                      r"\s*:\s*ok=(\d+)\s+changed=(\d+)\s+unreachable=(\d+)\s+failed=(\d+)", raw)
    if not match:
        return "unavailable", False, task_count
    recap = "ok=%s changed=%s unreachable=%s failed=%s" % match.groups()
    return recap, int(match.group(3)) == 0 and int(match.group(4)) == 0, task_count


def _v2_check_record(request: ManagedV2Request, host: str, plan: dict) -> dict:
    record = _managed_check_record(_v2_path(request.request_id, host, "check.json"))
    output = _v2_path(request.request_id, host, "check.log")
    if (record.get("host") != host or record.get("plan") != plan
            or record.get("diff_digest") != hashlib.sha256(trusted_file(output)).hexdigest()):
        raise Reject("managed check scope or diff changed")
    return record


def _v2_safety_digest(request_id: str, host: str, check: dict,
                      backup_ref: str, oob_ref: str, change_ref: str) -> str:
    """Require independently prepared root-local rollback and OOB evidence."""
    path = _v2_path(request_id, host, "safety.json")
    try:
        raw = trusted_file(path)
        safety = json.loads(raw, object_pairs_hook=unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise Reject("root-local safety preflight unavailable") from exc
    if (type(safety) is not dict or set(safety) != {"version", "request_id", "change_id",
            "host", "scope_digest", "backup_ref", "oob_ref", "expires_at"}
            or type(safety["version"]) is not int or safety["version"] != 1
            or safety["request_id"] != request_id
            or safety["change_id"] != change_ref or safety["host"] != host
            or safety["scope_digest"] != check["plan"]["scope_digest"]
            or safety["backup_ref"] != backup_ref or safety["oob_ref"] != oob_ref
            or type(safety["expires_at"]) is not int
            or safety["expires_at"] <= int(time.time())):
        raise Reject("root-local safety preflight mismatch")
    return hashlib.sha256(raw).hexdigest()


def issue_managed_v2_approval(request_id: str, host: str, issuer: str,
                              reason: str, ttl: int = 900, *, backup_ref: str | None = None,
                              oob_ref: str | None = None, change_ref: str | None = None) -> str:
    canonical_uuid(request_id)
    managed_identifier(host)
    managed_identifier(issuer)
    for reference in (backup_ref, oob_ref, change_ref):
        managed_identifier(reference)
    if type(reason) is not str or not reason.strip() or len(reason) > 512 or type(ttl) is not int or not 1 <= ttl <= 3600:
        raise Reject("invalid manual approval")
    with deployment_lock():
        policy, fingerprint = policy_and_hash()
        private_directory(STATE_DIR)
        private_directory(APPROVAL_DIR)
        check = _managed_check_record(_v2_path(request_id, host, "check.json"))
        if check.get("plan", {}).get("playbook_id") not in ("ubuntu_hardening", "debian_hardening"):
            raise Reject("read-only playbook cannot be approved for apply")
        if (check.get("host") != host or check.get("plan", {}).get("release_digest") != fingerprint
                or check.get("diff_digest") != hashlib.sha256(
                    trusted_file(_v2_path(request_id, host, "check.log"))).hexdigest()):
            raise Reject("managed check evidence changed")
        if change_ref != check["plan"].get("change_id"):
            raise Reject("change reference does not match checked scope")
        safety_digest = _v2_safety_digest(request_id, host, check,
                                          backup_ref, oob_ref, change_ref)
        approval_id = str(uuid.uuid4())
        _exclusive_record(APPROVAL_DIR / (approval_id + ".v2.json"),
                          {"version": 2, "approval_id": approval_id, "request_id": request_id,
                           "host": host, "scope_digest": check["plan"]["scope_digest"],
                           "diff_digest": check["diff_digest"], "issuer": issuer,
                           "reason": reason, "expires_at": int(time.time()) + ttl,
                           "backup_ref": backup_ref, "oob_ref": oob_ref,
                           "change_ref": change_ref, "safety_digest": safety_digest})
        return approval_id


def _v2_validate_approval(approval_id: str, request: ManagedV2Request,
                          host: str, check: dict) -> Path:
    source = APPROVAL_DIR / (canonical_uuid(approval_id) + ".v2.json")
    try:
        approval = json.loads(trusted_file(source), object_pairs_hook=unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise Reject("manual approval unavailable") from exc
    if (type(approval) is not dict or approval.get("version") != 2
            or approval.get("approval_id") != approval_id
            or approval.get("request_id") != request.request_id or approval.get("host") != host
            or approval.get("scope_digest") != check["plan"]["scope_digest"]
            or approval.get("diff_digest") != check["diff_digest"]
            or approval.get("change_ref") != request.change_id
            or any(type(approval.get(key)) is not str or not ID.fullmatch(approval[key])
                   for key in ("backup_ref", "oob_ref"))
            or approval.get("safety_digest") != _v2_safety_digest(
                request.request_id, host, check, approval.get("backup_ref"),
                approval.get("oob_ref"), approval.get("change_ref"))
            or type(approval.get("expires_at")) is not int
            or approval["expires_at"] <= int(time.time())):
        raise Reject("manual approval scope or lifetime mismatch")
    return source


def _v2_publish_terminal(request: ManagedV2Request, host: str, plan: dict,
                         terminal: dict, terminal_path: Path) -> None:
    """Replay a durable terminal into JSONL before releasing the host blocker."""
    marker = _v2_path(request.request_id, host, "terminal-published.json")
    digest = hashlib.sha256(trusted_file(terminal_path)).hexdigest()
    if marker.exists():
        published = json.loads(trusted_file(marker), object_pairs_hook=unique_object)
        if published != {"version": 1, "terminal_digest": digest}:
            raise Reject("terminal publication marker changed")
    else:
        _v2_event(terminal["status"], request, host, plan)
        _exclusive_record(marker, {"version": 1, "terminal_digest": digest})
    active = STATE_DIR / (host + ".managed-v2.active")
    if active.exists():
        blocker = json.loads(trusted_file(active), object_pairs_hook=unique_object)
        if blocker != {"request_id": request.request_id, "scope_digest": plan["scope_digest"]}:
            raise Reject("host blocker belongs to another execution")
        active.unlink()
        sync_directory(STATE_DIR)


@contextmanager
def _v2_host_locks(hosts: tuple[str, ...]):
    """Exclude the legacy gateway for every member before a batch can start."""
    import fcntl
    descriptors = []
    try:
        for host in hosts:
            fd = os.open(STATE_DIR / (host + ".lock"),
                         os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            descriptors.append(fd)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise Reject("target busy") from exc
        yield
    finally:
        for fd in descriptors:
            os.close(fd)


def run_managed_v2(request: ManagedV2Request) -> int:
    """Wazuh orders only; root-owned check evidence and approvals gate apply."""
    with deployment_lock():
        policy, fingerprint = policy_and_hash()
        private_directory(STATE_DIR)
        private_directory(APPROVAL_DIR)
        inventory = inventory_groups(policy, str(uuid.uuid4()))
        unique_target_addresses(policy, inventory)
        hosts, plan = _v2_plan(policy, fingerprint, request, inventory)
        with _v2_host_locks(hosts):
            if request.mode == "apply":
                receipts = [_v2_path(request.request_id, host, "terminal.json") for host in hosts]
                if any(path.exists() for path in receipts):
                    terminal = []
                    for host, path in zip(hosts, receipts):
                        if not path.exists():
                            continue
                        item = json.loads(trusted_file(path), object_pairs_hook=unique_object)
                        if (type(item) is not dict or item.get("plan") != plan
                                or item.get("host") != host or item.get("version") != 2
                                or item.get("approval_id") != request.approvals[host]):
                            raise Reject("managed apply replay scope changed")
                        _v2_publish_terminal(request, host, plan, item, path)
                        terminal.append(item)
                    if len(terminal) != len(hosts):
                        raise Reject("partial terminal state requires manual reconciliation")
                    return 0 if all(item.get("status") == "completed" for item in terminal) else 1
            task_digests = {host: _v2_preflight_tasks(policy, request, host, plan)
                            for host in hosts}
            if request.mode == "apply":
                checks = {host: _v2_check_record(request, host, plan) for host in hosts}
                if any(checks[host].get("task_digest") != task_digests[host] for host in hosts):
                    raise Reject("selected Ansible tasks changed after check")
                approvals = {host: _v2_validate_approval(request.approvals[host], request, host, checks[host])
                             for host in hosts}
                for host in hosts:
                    receipt = _v2_path(request.request_id, host, "terminal.json")
                    active = STATE_DIR / (host + ".managed-v2.active")
                    if active.exists():
                        raise Reject("host execution ambiguous or busy")
                    if receipt.exists():
                        raise Reject("managed apply already has terminal receipt")
                # Durable per-host blockers precede approval consumption or execution.
                for host in hosts:
                    _exclusive_record(STATE_DIR / (host + ".managed-v2.active"),
                                      {"request_id": request.request_id, "scope_digest": plan["scope_digest"]})
                for host in hosts:
                    source = approvals[host]
                    os.link(source, source.with_suffix(".consumed"), follow_symlinks=False)
                    sync_directory(APPROVAL_DIR)
                    source.unlink()
                    sync_directory(APPROVAL_DIR)
            failed = False
            for host in hosts:
                check_path = _v2_path(request.request_id, host, "check.json")
                output = _v2_path(request.request_id, host,
                                  "check.log" if request.mode == "check" else "apply.log")
                if request.mode == "check" and check_path.exists():
                    _v2_check_record(request, host, plan)
                    continue
                if output.exists():
                    raise Reject("incomplete managed execution blocks replay")
                vars_file = _v2_vars_file(policy, request, host)
                try:
                    args = _v2_args(policy, request, host, plan, vars_file)
                    _v2_event("accepted", request, host, plan)
                    _v2_event("started", request, host, plan)
                    code, truncated = run_private(args, Path(policy["ansible_root"]),
                                                  policy["service_user"], output)
                    recap, clean, task_count = _v2_recap(output, host)
                    _v2_event("progress", request, host, plan, task_count=task_count)
                    _v2_event("recap", request, host, plan, recap=recap)
                    success = code == 0 and not truncated and clean
                    if JOBS[request.playbook_id][2] == "verify":
                        _v2_event("verification", request, host, plan,
                                  verification="passed" if success else "failed")
                    elif request.mode == "apply":
                        _v2_event("verification", request, host, plan,
                                  verification="pending")
                    if request.mode == "check":
                        if success:
                            _exclusive_record(check_path, {"version": 1, "host": host, "plan": plan,
                                                           "task_digest": task_digests[host],
                                                           "diff_digest": hashlib.sha256(trusted_file(output)).hexdigest()})
                    else:
                        terminal_path = _v2_path(request.request_id, host, "terminal.json")
                        terminal = {"version": 2, "host": host, "plan": plan,
                                    "approval_id": request.approvals[host], "exit_code": code,
                                    "recap": recap, "status": "completed" if success else "failed"}
                        _exclusive_record(terminal_path, terminal)
                        _v2_publish_terminal(request, host, plan, terminal, terminal_path)
                    if request.mode == "check":
                        _v2_event("completed" if success else "failed", request, host, plan)
                    failed |= not success
                except Exception:
                    # A started process without a durable terminal is not safe to replay.
                    if request.mode == "apply":
                        try:
                            _v2_event("ambiguous", request, host, plan)
                        except (OSError, Reject):
                            pass
                    raise
                finally:
                    if vars_file is not None:
                        vars_file.unlink(missing_ok=True)
            return 1 if failed else 0


def trusted_file(path: Path, *, owner: int = 0) -> bytes:
    """Reject links and non-root writable ancestors before opening a file."""
    if not path.is_absolute():
        raise Reject("absolute trusted path required")
    for ancestor in (path, *path.parents):
        metadata = ancestor.lstat()
        if (metadata.st_uid != owner or metadata.st_mode & 0o022
                or stat.S_ISLNK(metadata.st_mode)):
            raise Reject("untrusted file path")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(fd)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != owner
                or metadata.st_mode & 0o022 or metadata.st_nlink != 1):
            raise Reject("untrusted file")
        if metadata.st_size > MAX_TRUSTED_FILE:
            raise Reject("file too large")
        with os.fdopen(os.dup(fd), "rb") as stream:
            data = stream.read(MAX_TRUSTED_FILE + 1)
        if len(data) > MAX_TRUSTED_FILE or len(data) != metadata.st_size:
            raise Reject("file changed while reading")
        return data
    finally:
        os.close(fd)


def private_directory(path: Path) -> None:
    metadata = path.lstat()
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0
            or metadata.st_mode & 0o077):
        raise Reject("root-private directory required")
    for ancestor in path.parents:
        metadata = ancestor.lstat()
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0
                or metadata.st_mode & 0o022):
            raise Reject("untrusted private directory path")


def service_directory(path: Path, uid: int) -> None:
    metadata = path.lstat()
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != uid
            or metadata.st_mode & 0o077):
        raise Reject("private service scratch required")
    for ancestor in path.parents:
        metadata = ancestor.lstat()
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0
                or metadata.st_mode & 0o022):
            raise Reject("untrusted service scratch path")


def trusted_tree_digest(root: Path) -> bytes:
    """Bind approvals to every source and inventory variable file in a tree."""
    if not root.is_absolute():
        raise Reject("absolute trusted tree required")
    for ancestor in (root, *root.parents):
        metadata = ancestor.lstat()
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0
                or metadata.st_mode & 0o022):
            raise Reject("untrusted source directory")
    digest = hashlib.sha256()
    for current, directories, files in os.walk(root, followlinks=False):
        directories.sort()
        for name in sorted(directories):
            path = Path(current) / name
            metadata = path.lstat()
            if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0
                    or metadata.st_mode & 0o022):
                raise Reject("untrusted source directory")
            digest.update(b"D\0" + path.relative_to(root).as_posix().encode() + b"\0")
        for name in sorted(files):
            path = Path(current) / name
            relative = path.relative_to(root).as_posix().encode("utf-8")
            metadata = path.lstat()
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
                    or metadata.st_mode & 0o022 or metadata.st_nlink != 1):
                raise Reject("untrusted runtime or source file")
            digest.update(b"F\0" + relative + b"\0" + str(metadata.st_size).encode()
                          + b"\0" + str(stat.S_IMODE(metadata.st_mode)).encode() + b"\0")
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                if os.fstat(fd).st_ino != metadata.st_ino:
                    raise Reject("source changed during fingerprint")
                with os.fdopen(os.dup(fd), "rb") as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(chunk)
                if os.fstat(fd).st_size != metadata.st_size:
                    raise Reject("source changed during fingerprint")
            finally:
                os.close(fd)
            digest.update(b"\0")
    return digest.digest()


@contextmanager
def deployment_lock(*, exclusive: bool = False):
    """Never create/replace this root-private, stable-inode cooperative lock."""
    import fcntl
    if os.getuid() != 0 or os.geteuid() != 0:
        raise Reject("root required")
    private_directory(DEPLOYMENT_LOCK.parent)
    fd = os.open(DEPLOYMENT_LOCK, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(fd)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
                or metadata.st_mode & 0o077 or metadata.st_nlink != 1
                or metadata.st_size != 0):
            raise Reject("invalid deployment lock")
        fcntl.flock(fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        current = DEPLOYMENT_LOCK.lstat()
        if (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise Reject("deployment lock replaced")
        # Never pass this descriptor to the service: it could explicitly unlock it.
        yield
    except BlockingIOError as exc:
        raise Reject("deployment busy") from exc
    finally:
        os.close(fd)


def release_digest(policy: dict, raw: bytes, *, legacy_active: bool = False) -> bytes:
    release = RELEASES_ROOT / identifier(policy["release_id"])
    payload = release / "payload"
    if (policy["ansible_root"] != str(payload / "ansible")
            or policy["ansible_bin_dir"] != str(payload / "runtime" / "bin")
            or policy["inventory"] != str(payload / "inventory" / "hosts.yml")):
        raise Reject("policy paths must belong to the versioned release")
    descriptor_raw = trusted_file(release / "release.json")
    try:
        descriptor = json.loads(descriptor_raw, object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise Reject("invalid release descriptor") from exc
    tree = trusted_tree_digest(payload)
    for directory in ("home", "collections", "plugins", "runtime", "runtime/python"):
        trusted_tree_digest(payload / directory)
    bootstrap = payload / "runtime" / "runtime_bootstrap.py"
    bootstrap_hash = hashlib.sha256(trusted_file(bootstrap)).hexdigest()
    accepted_bootstraps = {BOOTSTRAP_SHA256}
    # Migration only: prior pins are valid for the exact active release IDs.
    # Candidate activation and ordinary jobs never opt into these exceptions.
    if legacy_active and policy["release_id"] == "lab_v3":
        accepted_bootstraps.add(LEGACY_LAB_V3_BOOTSTRAP_SHA256)
    legacy_v14 = (legacy_active and policy["release_id"] == "lab_v14"
                  and bootstrap_hash == LEGACY_LAB_V14_BOOTSTRAP_SHA256)
    if legacy_v14:
        accepted_bootstraps.add(LEGACY_LAB_V14_BOOTSTRAP_SHA256)
    if bootstrap_hash not in accepted_bootstraps:
        raise Reject("sealed runtime bootstrap mismatch")
    for command in ("playbook", "inventory"):
        launcher = payload / "runtime" / "bin" / ("ansible-" + command)
        expected_launcher = (legacy_lab_v14_launcher(bootstrap, command)
                             if legacy_v14 else canonical_launcher(bootstrap, command))
        if trusted_file(launcher) != expected_launcher:
            raise Reject("sealed runtime launcher mismatch")
    expected = {"version": 1, "release_id": policy["release_id"],
                "policy_sha256": hashlib.sha256(raw).hexdigest(),
                "payload_sha256": tree.hex()}
    if descriptor != expected or type(descriptor.get("version")) is not int:
        raise Reject("release descriptor mismatch")
    if trusted_file(release / "policy.json") != raw:
        raise Reject("active policy differs from sealed release policy")
    return descriptor_raw + tree


def activate_release(release_id: str) -> None:
    """Activate an already prepared release; never edit any existing release."""
    with deployment_lock(exclusive=True):
        candidate = RELEASES_ROOT / identifier(release_id) / "policy.json"
        policy, _ = policy_and_hash(candidate)
        if policy["release_id"] != release_id:
            raise Reject("candidate release identity mismatch")
        private_directory(POLICY_PATH.parent)
        if POLICY_PATH.is_symlink():
            raise Reject("untrusted policy path")
        if POLICY_PATH.exists():
            active, _ = policy_and_hash(_legacy_active=True)
            if active["release_id"] == release_id:
                raise Reject("new release required")
        raw = trusted_file(candidate)
        # A release identity is never reactivated: rollback needs a fresh ID,
        # so a former release cannot make a stale approval valid again.
        private_directory(ACTIVATION_DIR)
        marker = ACTIVATION_DIR / release_id
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        sync_directory(ACTIVATION_DIR)
        temporary = POLICY_PATH.parent / (".policy-" + str(uuid.uuid4()))
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, POLICY_PATH)
            sync_directory(POLICY_PATH.parent)
        finally:
            temporary.unlink(missing_ok=True)


def policy_and_hash(path: Path | None = None, *, _legacy_active: bool = False) -> tuple[dict, str]:
    path = POLICY_PATH if path is None else path
    if _legacy_active and path != POLICY_PATH:
        raise Reject("legacy bootstrap is valid only for active policy migration")
    raw = trusted_file(path)
    if path.stat().st_mode & 0o077:
        raise Reject("root-private policy required")
    try:
        policy = json.loads(raw, object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Reject("invalid policy") from exc
    if (type(policy) is not dict or set(policy) != {"version", "release_id", "ansible_root", "ansible_bin_dir", "inventory", "service_user", "targets", "controls"}
            or type(policy["version"]) is not int or policy["version"] != 2
            or type(policy["targets"]) is not dict or type(policy["controls"]) is not dict):
        raise Reject("invalid policy schema")
    root = Path(policy["ansible_root"])
    binaries = Path(policy["ansible_bin_dir"])
    inventory = Path(policy["inventory"])
    release_hash = release_digest(policy, raw, legacy_active=_legacy_active)
    if (not root.is_absolute() or not inventory.is_absolute()
            or inventory.suffix not in (".yml", ".yaml")
            or not root.is_dir()):
        raise Reject("invalid policy paths")
    identifier(policy["service_user"])
    account = pwd.getpwnam(policy["service_user"])
    if account.pw_uid == 0:
        raise Reject("non-root service account required")
    service_directory(LOCAL_TEMP, account.pw_uid)
    inventory_raw = trusted_file(inventory)
    configuration_raw = trusted_file(root / "ansible.cfg")
    trusted_file(binaries / "ansible-playbook")
    trusted_file(binaries / "ansible-inventory")
    for job_os, playbook, _ in JOBS.values():
        trusted_file(root / "playbooks" / playbook)
    for target, data in policy["targets"].items():
        identifier(target)
        if (type(data) is not dict or set(data) != {"host", "os"}
                or data["os"] not in ("ubuntu24", "debian12")):
            raise Reject("invalid target")
        identifier(data["host"])
        if data["host"] in ("all", "ungrouped"):
            raise Reject("inventory group is not a host")
    aliases = [data["host"] for data in policy["targets"].values()]
    if len(aliases) != len(set(aliases)):
        raise Reject("inventory host aliases must be unique")
    for control, data in policy["controls"].items():
        identifier(control)
        if (type(data) is not dict or set(data) != {"tag", "os"}
                or not CONTROL_TAG.fullmatch(data["tag"])
                or type(data["os"]) is not list or not data["os"]
                or any(item not in ("ubuntu24", "debian12") for item in data["os"])):
            raise Reject("invalid control")
        for os_name in data["os"]:
            if REMEDIATION_CONTROLS[os_name].get(control) != data["tag"]:
                raise Reject("control has no reviewed remediation capability")
            role = "cis_ubuntu_2404" if os_name == "ubuntu24" else "cis_debian_12"
            # A numerical pattern is not enough: require a tag in the installed role.
            role_text = trusted_file(root / "roles" / role / "tasks" / "main.yml").decode("utf-8")
            if not re.search(r"^\s*tags:\s*\[[^\]\n]*\b" + re.escape(data["tag"]) + r"\b[^\]\n]*\]", role_text, re.MULTILINE):
                raise Reject("control tag absent from installed role")
    digest = hashlib.sha256(raw + b"\0" + inventory_raw + b"\0"
                            + configuration_raw + trusted_tree_digest(root / "roles")
                            + trusted_tree_digest(root / "playbooks")
                            + trusted_tree_digest(inventory.parent)
                            + release_hash
                            + trusted_file(ENTRYPOINT)
                            + json.dumps(runtime_environment(root), sort_keys=True).encode()).hexdigest()
    return policy, digest


def selection(policy: dict, job: str, target: str, control: str) -> tuple[str, str, str, list[str]]:
    if job not in JOBS or target not in policy["targets"]:
        raise Reject("job or target not allowed")
    os_name, playbook, kind = JOBS[job]
    data = policy["targets"][target]
    if data["os"] != os_name:
        raise Reject("target operating system mismatch")
    if kind == "hardening":
        if control not in policy["controls"] or os_name not in policy["controls"][control]["os"]:
            raise Reject("control not allowed")
        tag = policy["controls"][control]["tag"]
        if REMEDIATION_CONTROLS[os_name].get(control) != tag:
            raise Reject("control has no reviewed remediation capability")
        extras = list(GATES[os_name])
    else:
        if control != "none":
            raise Reject("control not accepted for read-only job")
        tag, extras = "", []
    return data["host"], playbook, tag, extras


def approval_file(approval_id: str) -> Path:
    try:
        if str(uuid.UUID(approval_id)) != approval_id:
            raise ValueError
    except ValueError as exc:
        raise Reject("invalid approval identifier") from exc
    return APPROVAL_DIR / (approval_id + ".json")


def issue_approval(job: str, target: str, control: str, change_id: str,
                   ttl: int = 900) -> str:
    # No runtime flag can enable this. Deployment exclusion must survive
    # gateway death before this root-local approval path can be implemented.
    raise Reject("approval issuance disabled: crash-safe supervision unavailable")


def sync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def consume_approval(approval_id: str, job: str, target: str, control: str,
                     fingerprint: str) -> str:
    """An approval is burned before process launch; crashes cannot replay it."""
    private_directory(APPROVAL_DIR)
    path = approval_file(approval_id)
    try:
        document = json.loads(trusted_file(path), object_pairs_hook=unique_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Reject("approval unavailable") from exc
    try:
        if path.stat().st_mode & 0o077:
            raise Reject("approval file must be root-private")
    except OSError as exc:
        raise Reject("approval unavailable") from exc
    if (type(document) is not dict or set(document) != {"version", "job", "target", "control", "change_id", "fingerprint", "expires"}
            or type(document["version"]) is not int or document["version"] != 1 or document["job"] != job
            or document["target"] != target or document["control"] != control
            or document["fingerprint"] != fingerprint or type(document["expires"]) is not int
            or document["expires"] <= int(time.time())):
        raise Reject("approval scope, policy or lifetime mismatch")
    identifier(document["change_id"])
    # rename is atomic; racing consumers cannot both rename the source.
    consumed = APPROVAL_DIR / (approval_id + ".consumed")
    if consumed.exists():
        raise Reject("approval already consumed")
    try:
        os.rename(path, consumed)
        sync_directory(APPROVAL_DIR)
    except OSError as exc:
        raise Reject("approval consume failed") from exc
    return document["change_id"]


def drop_service(name: str) -> None:
    account = pwd.getpwnam(name)
    os.initgroups(account.pw_name, account.pw_gid)
    os.setgid(account.pw_gid)
    os.setuid(account.pw_uid)


def runtime_environment(root: Path) -> dict[str, str]:
    """Pin loader paths; only temporary files belong to the service account."""
    payload = root.parent
    plugins = payload / "plugins"
    environment = {
        "HOME": str(payload / "home"), "ANSIBLE_HOME": str(payload / "home"), "PATH": PATH,
        "LANG": "C.UTF-8", "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
        "ANSIBLE_CONFIG": str(root / "ansible.cfg"), "ANSIBLE_NOCOLOR": "1",
        "ANSIBLE_COLLECTIONS_PATH": str(payload / "collections"),
        "ANSIBLE_COLLECTIONS_SCAN_SYS_PATH": "false",
        "ANSIBLE_ROLES_PATH": str(root / "roles"),
        "ANSIBLE_LOCAL_TEMP": str(LOCAL_TEMP), "TMPDIR": str(LOCAL_TEMP),
        "ANSIBLE_SSH_CONTROL_PATH_DIR": str(LOCAL_TEMP),
        "ANSIBLE_LIBRARY": str(plugins / "modules"),
        "ANSIBLE_MODULE_UTILS": str(plugins / "module_utils"),
    }
    for kind in PLUGIN_TYPES:
        environment["ANSIBLE_" + kind + "_PLUGINS"] = str(plugins / kind.lower())
    return environment


def run_private(args: list[str], cwd: Path, service: str, output: Path,
                *, timeout: int = TIMEOUT, lock_fd: int | None = None) -> tuple[int, bool]:
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    environment = runtime_environment(cwd)
    with os.fdopen(fd, "wb") as stream:
        process = subprocess.Popen(args, cwd=cwd, shell=False, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   env=environment, start_new_session=True,
                                   pass_fds=() if lock_fd is None else (lock_fd,),
                                   preexec_fn=lambda: drop_service(service))
        deadline = time.monotonic() + timeout
        written = 0
        truncated = False
        leftover = False
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    left = deadline - time.monotonic()
                    if left <= 0:
                        raise subprocess.TimeoutExpired(args[0], timeout)
                    for key, _ in selector.select(timeout=left):
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        available = MAX_OUTPUT - written
                        truncated |= len(chunk) > available
                        if available > 0:
                            stream.write(chunk[:available])
                            written += min(len(chunk), available)
            # Do not reap the leader yet: retaining its PID prevents reuse of
            # the process-group ID while descendants are drained below.
            while os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                if time.monotonic() >= deadline:
                    raise subprocess.TimeoutExpired(args[0], timeout)
                time.sleep(0.02)
            leftover = live_process_group(process.pid)
        finally:
            # EOF/leader exit does not prove its process group has completed.
            # Abort leftover members before releasing root's deployment lock.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            while live_process_group(process.pid):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                time.sleep(0.02)
            process.wait()
            process.stdout.close()
        return (-signal.SIGKILL if leftover else process.returncode), truncated


def live_process_group(group: int) -> bool:
    """Linux /proc is part of the trusted OS boundary; zombies execute no code."""
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
        except (FileNotFoundError, ProcessLookupError):
            continue
        if int(fields[2]) == group and fields[0] != "Z":
            return True
    return False


def inventory_groups(policy: dict, request_id: str) -> dict:
    root = Path(policy["ansible_root"])
    output = STATE_DIR / (request_id + ".inventory.log")
    command = [str(Path(policy["ansible_bin_dir"]) / "ansible-inventory"),
               "-i", policy["inventory"], "--list"]
    code, truncated = run_private(command, root, policy["service_user"], output,
                                  timeout=INVENTORY_TIMEOUT)
    if code != 0 or truncated:
        raise Reject("inventory inspection failed")
    try:
        inventory = json.loads(output.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Reject("inventory inspection invalid") from exc
    if type(inventory) is not dict:
        raise Reject("inventory inspection invalid")
    return inventory


def group_contains(inventory: dict, group: str, host: str,
                   seen: set[str] | None = None) -> bool:
    if seen is None:
        seen = set()
    if group in seen:
        return False
    seen.add(group)
    entry = inventory.get(group)
    if type(entry) is not dict:
        return False
    hosts = entry.get("hosts", [])
    children = entry.get("children", [])
    if type(hosts) is not list or type(children) is not list:
        raise Reject("invalid inventory group")
    return host in hosts or any(type(child) is str and group_contains(inventory, child, host, seen.copy())
                                for child in children)


def unique_target_addresses(policy: dict, inventory: dict) -> None:
    metadata = inventory.get("_meta")
    variables = metadata.get("hostvars") if type(metadata) is dict else None
    if type(variables) is not dict:
        raise Reject("inventory host variables unavailable")
    addresses = []
    for target in policy["targets"].values():
        host = target["host"]
        values = variables.get(host)
        if type(values) is not dict:
            raise Reject("target host variables unavailable")
        address = values.get("ansible_host", host)
        if type(address) is not str or not address:
            raise Reject("invalid target address")
        addresses.append(address)
    if len(addresses) != len(set(addresses)):
        raise Reject("multiple target aliases resolve to one address")


def emit(status: str, request_id: str, job: str, target: str, control: str,
         mode: str, *, change_id: str = "none") -> None:
    value = {"timestamp": datetime.now(timezone.utc).isoformat(),
             "source": "ansible-wazuh-job", "request_id": request_id,
             "status": status, "job_id": job, "target_id": target,
             "control_id": control, "mode": mode, "change_id": change_id}
    fd = os.open(EVENT_LOG, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        metadata = os.fstat(fd)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
                or metadata.st_mode & 0o077 or metadata.st_nlink != 1):
            raise Reject("private event log required")
        os.write(fd, (json.dumps(value, separators=(",", ":")) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)


def run_job(job: str, target: str, control: str, approval: str) -> int:
    if approval != "none":
        # Cooperative locking is not crash-safe supervision. Keep apply closed
        # until root's deployment lock survives gateway/process-tree failures.
        raise Reject("apply disabled: crash-safe supervision unavailable")
    with deployment_lock():
        return run_locked_job(job, target, control)


def run_locked_job(job: str, target: str, control: str) -> int:
    """The caller retains the deployment lock across verification and launch."""
    request_id = str(uuid.uuid4())
    mode = "check"
    if os.geteuid() != 0 or os.getuid() != 0:
        raise Reject("root required")
    policy, fingerprint = policy_and_hash()
    host, playbook, tag, extras = selection(policy, job, target, control)
    private_directory(STATE_DIR)
    import fcntl
    lock_path = STATE_DIR / (host + ".lock")
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        inventory = inventory_groups(policy, request_id)
        unique_target_addresses(policy, inventory)
        required_group = ("ubuntu_2404" if job == "ubuntu_verify" else
                          "ubuntu" if JOBS[job][0] == "ubuntu24" else "debian_12")
        if host in inventory or not group_contains(inventory, required_group, host):
            raise Reject("target absent from required inventory group")
        # Defense in depth; exclusion comes from the cooperative deployment lock.
        if policy_and_hash()[1] != fingerprint:
            raise Reject("policy or inventory changed")
        change_id = "none"
        args = [str(Path(policy["ansible_bin_dir"]) / "ansible-playbook"),
                str(Path(policy["ansible_root"]) / "playbooks" / playbook),
                "-i", policy["inventory"], "--limit", host]
        if tag:
            args += ["--tags", tag]
        for item in extras:
            args += ["-e", item]
        args += ["--check", "--diff"]
        emit("accepted", request_id, job, target, control, mode, change_id=change_id)
        output = STATE_DIR / (request_id + ".ansible.log")
        try:
            code, truncated = run_private(args, Path(policy["ansible_root"]),
                                          policy["service_user"], output, lock_fd=lock_fd)
        except (OSError, subprocess.TimeoutExpired):
            emit("failed", request_id, job, target, control, mode, change_id=change_id)
            return 1
        emit("completed" if code == 0 and not truncated else "failed", request_id, job, target,
             control, mode, change_id=change_id)
        return 0 if code == 0 and not truncated else 1
    except BlockingIOError as exc:
        raise Reject("target busy") from exc
    finally:
        os.close(lock_fd)


def secure_entrypoint() -> None:
    if sys.platform != "linux" or os.getuid() != 0 or os.geteuid() != 0:
        raise Reject("root Linux entrypoint required")
    if Path(__file__).absolute() != ENTRYPOINT:
        raise Reject("installed entrypoint required")
    trusted_file(ENTRYPOINT)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    options = parser.add_mutually_exclusive_group()
    options.add_argument("--wazuh", action="store_true")
    options.add_argument("--issue", action="store_true")
    options.add_argument("--managed-approve", metavar="REQUEST_ID")
    options.add_argument("--managed-v2-approve", metavar="REQUEST_ID")
    parser.add_argument("--backup-ref")
    parser.add_argument("--oob-ref")
    parser.add_argument("--change-ref")
    options.add_argument("--activate", metavar="RELEASE_ID")
    parser.add_argument("--job")
    parser.add_argument("--target")
    parser.add_argument("--control")
    parser.add_argument("--change-id")
    parser.add_argument("--ttl", type=int, default=900)
    parser.add_argument("--issuer")
    parser.add_argument("--reason")
    args = parser.parse_args()
    observed = ("unknown", "unknown", "unknown", "unknown")
    request = None
    try:
        secure_entrypoint()
        if args.activate:
            if any((args.job, args.target, args.control, args.change_id)) or args.ttl != 900:
                raise Reject("activation does not accept issue scope")
            activate_release(args.activate)
            return 0
        if args.issue:
            if not all((args.job, args.target, args.control, args.change_id)):
                raise Reject("missing issue scope")
            print(issue_approval(args.job, args.target, args.control, args.change_id, args.ttl))
            return 0
        if args.managed_approve:
            if (any((args.job, args.target, args.control, args.change_id))
                    or not args.issuer or not args.reason):
                raise Reject("managed approval needs request, issuer and reason")
            print(issue_managed_approval(args.managed_approve, args.issuer,
                                         args.reason, args.ttl))
            return 0
        if args.managed_v2_approve:
            if (any((args.job, args.control, args.change_id)) or not args.target
                    or not args.issuer or not args.reason or not args.backup_ref
                    or not args.oob_ref or not args.change_ref):
                raise Reject("managed-v2 approval needs scope, issuer, reason and safety references")
            print(issue_managed_v2_approval(args.managed_v2_approve, args.target,
                                            args.issuer, args.reason, args.ttl,
                                            backup_ref=args.backup_ref, oob_ref=args.oob_ref,
                                            change_ref=args.change_ref))
            return 0
        if (any((args.job, args.target, args.control, args.change_id,
                 args.issuer, args.reason, args.backup_ref, args.oob_ref,
                 args.change_ref)) or args.ttl != 900):
            raise Reject("issue options require --issue")
        line = sys.stdin.buffer.readline(MAX_REQUEST + 1)
        request = parse_wazuh(line)
        if type(request) is LegacyCheckRequest:
            observed = (request.job_id, request.target_id, request.control_id, "check")
        elif type(request) is ManagedV2Request:
            observed = (request.playbook_id, "batch", request.selection_kind, request.mode)
        return dispatch_request(request)
    except (Reject, OSError, KeyError, TypeError, ValueError, ImportError,
            UnicodeError, subprocess.SubprocessError):
        # No attacker-controlled text or private Ansible output reaches Wazuh stdout.
        if not args.issue and not args.activate:
            try:
                if type(request) is ManagedV2Request:
                    emit("rejected", request.request_id, *observed,
                         change_id=request.change_id)
                else:
                    emit("rejected", str(uuid.uuid4()), *observed)
            except (OSError, Reject):
                pass
        return 2


if __name__ == "__main__":
    sys.exit(main())
