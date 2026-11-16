#!/usr/bin/python3 -I
"""Write the root-local safety preflight file that APPLY approval requires (root).

After a CHECK completed, the person responsible records where the host's backup
or snapshot is (``--backup-ref``) and how access is recovered out of band
(``--oob-ref``). This tool binds those references to the CHECK's exact scope and
writes ``<request_id>.<host>.v2.safety.json`` in the gateway's private state
directory. Only then can ``ansible-job --managed-v2-approve`` issue the
one-shot approval. The file layout is the contract checked by
managed_job._v2_safety_digest.

Standard library only. The file is created exclusively (never replaced), 0600.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import time
import uuid
from pathlib import Path

STATE_DIR = Path("/var/lib/ansible-wazuh/state")
ID = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}\Z")
HEX64 = re.compile(r"[0-9A-Fa-f]{64}\Z")
MAX_TTL = 86400
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
O_BINARY = getattr(os, "O_BINARY", 0)
SAFETY_KEYS = ("version", "request_id", "change_id", "host", "scope_digest",
               "backup_ref", "oob_ref", "expires_at")


class SafetyError(Exception):
    """The safety file must not be written."""


def identifier(value: str, what: str) -> str:
    # Same grammar as the gateway's managed_identifier: a bare digest is refused.
    if type(value) is not str or not ID.fullmatch(value) or HEX64.fullmatch(value):
        raise SafetyError(f"invalid {what}: must match [A-Za-z][A-Za-z0-9_.-]{{0,63}}")
    return value


def canonical_uuid(value: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError, TypeError) as exc:
        raise SafetyError("invalid request id") from exc
    if str(parsed) != value or parsed.int == 0:
        raise SafetyError("request id must be a lowercase hyphenated non-zero UUID")
    return value


def v2_path(state_dir: Path, request_id: str, host: str, suffix: str) -> Path:
    """Mirror of managed_job._v2_path."""
    return state_dir / (canonical_uuid(request_id) + "." + identifier(host, "host") + ".v2." + suffix)


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise SafetyError("duplicate JSON key in check evidence")
        value[key] = item
    return value


def load_check(path: Path, host: str) -> dict:
    try:
        raw = path.read_bytes()
        check = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SafetyError("no usable CHECK evidence for this request and host") from exc
    plan = check.get("plan") if type(check) is dict else None
    if (type(check) is not dict or check.get("version") != 1 or check.get("host") != host
            or type(plan) is not dict
            or plan.get("playbook_id") not in ("ubuntu_hardening", "debian_hardening")
            or type(plan.get("scope_digest")) is not str
            or not re.fullmatch(r"[0-9a-f]{64}", plan["scope_digest"])
            or type(plan.get("change_id")) is not str):
        raise SafetyError("CHECK evidence is malformed or not a hardening check")
    return check


def build_safety(request_id: str, host: str, check: dict, backup_ref: str, oob_ref: str,
                 ttl: int, now: int | None = None) -> dict:
    if type(ttl) is not int or not 60 <= ttl <= MAX_TTL:
        raise SafetyError(f"ttl must be 60..{MAX_TTL} seconds")
    current = int(time.time()) if now is None else now
    safety = {
        "version": 1, "request_id": canonical_uuid(request_id),
        "change_id": identifier(check["plan"]["change_id"], "change id"),
        "host": identifier(host, "host"),
        "scope_digest": check["plan"]["scope_digest"],
        "backup_ref": identifier(backup_ref, "backup reference"),
        "oob_ref": identifier(oob_ref, "out-of-band reference"),
        "expires_at": current + ttl,
    }
    assert tuple(sorted(safety)) == tuple(sorted(SAFETY_KEYS))
    return safety


def write_exclusive(path: Path, safety: dict) -> None:
    payload = (json.dumps(safety, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW | O_BINARY, 0o600)
    try:
        view = memoryview(payload)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)
    if hasattr(os, "O_DIRECTORY"):
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def require_private_state(state_dir: Path) -> None:
    if not hasattr(os, "geteuid"):
        raise SafetyError("a Linux controller is required")
    info = state_dir.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077):
        raise SafetyError(f"{state_dir} must be a root-private directory")


def prepare(state_dir: Path, request_id: str, host: str, backup_ref: str, oob_ref: str,
            ttl: int) -> tuple[Path, dict]:
    check = load_check(v2_path(state_dir, request_id, host, "check.json"), identifier(host, "host"))
    safety = build_safety(request_id, host, check, backup_ref, oob_ref, ttl)
    target = v2_path(state_dir, request_id, host, "safety.json")
    if target.exists() or target.is_symlink():
        raise SafetyError("a safety file already exists for this request and host")
    write_exclusive(target, safety)
    return target, safety


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--host", required=True, help="inventory alias of the checked host")
    parser.add_argument("--backup-ref", required=True,
                        help="identifier of the verified backup or snapshot (no free text)")
    parser.add_argument("--oob-ref", required=True,
                        help="identifier of the verified out-of-band recovery access")
    parser.add_argument("--ttl", type=int, default=7200, help="validity in seconds (60..86400)")
    parser.add_argument("--state-dir", type=Path, default=STATE_DIR, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        if args.state_dir == STATE_DIR:
            if hasattr(os, "geteuid") and os.geteuid() != 0:
                raise SafetyError("run as root")
            require_private_state(STATE_DIR)
        target, safety = prepare(args.state_dir, args.request_id, args.host, args.backup_ref,
                                 args.oob_ref, args.ttl)
    except (SafetyError, OSError) as exc:
        print("safety file not written: " + str(exc), file=sys.stderr)
        return 2
    print(f"wrote {target} (expires_at={safety['expires_at']})")
    print("Next, as root, issue the one-shot approval within that lifetime:")
    print(f"  /var/ossec/active-response/bin/ansible-job --managed-v2-approve {safety['request_id']}"
          f" --target {safety['host']} --issuer <approver_id> --reason \"<why>\""
          f" --backup-ref {safety['backup_ref']} --oob-ref {safety['oob_ref']}"
          f" --change-ref {safety['change_id']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
