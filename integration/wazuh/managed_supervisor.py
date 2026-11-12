"""Fail-closed local supervisor primitives for managed hardening.

This module is deliberately not a Wazuh entry point and never starts Ansible.
It creates durable, root-local approval/reservation/claim evidence that a
systemd unit may validate before a separately sealed worker is allowed to run.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid

from integration.wazuh import execution_state as state
from integration.wazuh import launch_claim
from integration.wazuh import retained_observation


IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}\Z")
HEX256 = re.compile(r"[0-9a-f]{64}\Z")
APPROVAL_DIR = Path("/var/lib/ansible-wazuh/managed-approvals")
LEASE_DIR = Path("/var/lib/ansible-wazuh/managed-leases")
MAX_TTL_SECONDS = 3600


class SupervisorRejected(ValueError):
    """A request is not authorized to cross the supervisor boundary."""


@dataclass(frozen=True)
class Approval:
    approval_id: str
    request_id: str
    release_id: str
    release_digest: str
    profile_digest: str
    inventory_profile_id: str
    host_profile_id: str
    section_profile_id: str
    target_alias: str
    section: str
    change_id: str
    diff_digest: str
    issuer: str
    reason: str
    issued_at: int
    expires_at: int


@dataclass(frozen=True)
class Reservation:
    request_id: str
    boot_id: str
    job_id: str
    target: str
    control: str
    release_digest: str
    approval_id: str
    change_id: str


def _identifier(value: object, field: str) -> str:
    if type(value) is not str or not IDENTIFIER.fullmatch(value):
        raise SupervisorRejected(f"invalid {field}")
    return value


def _uuid(value: object, field: str) -> str:
    if type(value) is not str:
        raise SupervisorRejected(f"invalid {field}")
    try:
        parsed = uuid.UUID(value)
    except ValueError as exc:
        raise SupervisorRejected(f"invalid {field}") from exc
    if str(parsed) != value or parsed.int == 0:
        raise SupervisorRejected(f"invalid {field}")
    return value


def _digest(value: object, field: str) -> str:
    if type(value) is not str or not HEX256.fullmatch(value):
        raise SupervisorRejected(f"invalid {field}")
    return value


def _approval_payload(approval: Approval) -> bytes:
    return (json.dumps({"version": 1, **asdict(approval)}, sort_keys=True,
                       separators=(",", ":")) + "\n").encode("ascii")


def create_approval(*, request_id: str, release_id: str, release_digest: str,
                    profile_digest: str, inventory_profile_id: str,
                    host_profile_id: str, section_profile_id: str,
                    target_alias: str, section: str, change_id: str,
                    diff_digest: str, issuer: str, reason: str,
                    issued_at: int, expires_at: int,
                    approval_id: str | None = None) -> Approval:
    """Validate every approval dimension before any durable write is attempted."""
    current = int(time.time())
    if (type(issued_at) is not int or issued_at > current or issued_at < current - MAX_TTL_SECONDS
            or type(expires_at) is not int or expires_at <= current
            or expires_at > issued_at + MAX_TTL_SECONDS):
        raise SupervisorRejected("invalid approval expiration")
    if type(reason) is not str or not reason.strip() or len(reason) > 512:
        raise SupervisorRejected("invalid approval reason")
    return Approval(
        _uuid(str(uuid.uuid4()) if approval_id is None else approval_id, "approval id"),
        _uuid(request_id, "request id"), _identifier(release_id, "release id"),
        _digest(release_digest, "release digest"),
        _digest(profile_digest, "profile digest"),
        _identifier(inventory_profile_id, "inventory profile"),
        _identifier(host_profile_id, "host profile"),
        _identifier(section_profile_id, "section profile"),
        _identifier(target_alias, "target alias"), _identifier(section, "section"),
        _identifier(change_id, "change id"), _digest(diff_digest, "diff digest"),
        _identifier(issuer, "issuer"), reason, issued_at, expires_at,
    )


def _approval_path(directory: Path, approval_id: str, suffix: str = ".json") -> Path:
    return directory / (_uuid(approval_id, "approval id") + suffix)


def _write_exclusive(path: Path, payload: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(payload)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise SupervisorRejected("incomplete durable write")
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    _sync_directory(path.parent)


def _sync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _private_root_directory(path: Path) -> None:
    """The fixed authority roots must not be writable by non-root users."""
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise SupervisorRejected("approval directory unavailable") from exc
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0
            or metadata.st_mode & 0o077 or path.is_symlink()):
        raise SupervisorRejected("root-private approval directory required")


def issue(approval: Approval, *, approval_directory: Path = APPROVAL_DIR) -> None:
    """Persist one complete approval only; partial authority never exists."""
    _validate_approval(approval)
    _private_root_directory(approval_directory)
    _write_exclusive(_approval_path(approval_directory, approval.approval_id), _approval_payload(approval))


def _validate_approval(approval: Approval) -> None:
    expected = create_approval(**asdict(approval))
    if expected != approval:
        raise SupervisorRejected("invalid approval")


def _read_approval(path: Path) -> Approval:
    try:
        raw = path.read_bytes()
        document = json.loads(raw, object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise SupervisorRejected("approval unavailable") from exc
    if type(document) is not dict or set(document) != {"version", *Approval.__dataclass_fields__} or document.pop("version") != 1:
        raise SupervisorRejected("invalid approval document")
    try:
        approval = Approval(**document)
        _validate_approval(approval)
    except (TypeError, SupervisorRejected) as exc:
        raise SupervisorRejected("invalid approval document") from exc
    return approval


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise SupervisorRejected("duplicate JSON key")
        value[key] = item
    return value


def validate_sealed_worker_manifest(manifest: object) -> str:
    """Accept only the installed worker identity, never a payload-selected path."""
    if type(manifest) is not dict or set(manifest) != {"kind", "launcher", "digest"}:
        raise SupervisorRejected("sealed worker manifest required")
    if (manifest["kind"] != "sealed-ansible-worker"
            or manifest["launcher"] != "/usr/local/lib/ansible-wazuh/managed-worker"):
        raise SupervisorRejected("unapproved worker launcher")
    return _digest(manifest["digest"], "worker digest")


def consume(*, approval_id: str, request_id: str, release_id: str,
            release_digest: str, profile_digest: str, inventory_profile_id: str,
            host_profile_id: str, section_profile_id: str, change_id: str,
            target_alias: str, section: str, diff_digest: str, now: int | None = None,
            approval_directory: Path = APPROVAL_DIR) -> Approval:
    """Burn the matching approval with a no-overwrite hard-link transition."""
    _private_root_directory(approval_directory)
    source = _approval_path(approval_directory, approval_id)
    approval = _read_approval(source)
    current = int(time.time()) if now is None else now
    identity = (request_id, release_id, release_digest, profile_digest,
                inventory_profile_id, host_profile_id, section_profile_id,
                target_alias, section, change_id, diff_digest)
    if (current >= approval.expires_at or identity != (approval.request_id,
            approval.release_id, approval.release_digest, approval.profile_digest,
            approval.inventory_profile_id, approval.host_profile_id,
            approval.section_profile_id, approval.target_alias, approval.section,
            approval.change_id, approval.diff_digest)):
        raise SupervisorRejected("approval scope or lifetime mismatch")
    consumed = _approval_path(approval_directory, approval_id, ".consumed")
    try:
        os.link(source, consumed, follow_symlinks=False)
        _sync_directory(approval_directory)
        os.unlink(source)
        _sync_directory(approval_directory)
    except OSError as exc:
        raise SupervisorRejected("approval already consumed or unavailable") from exc
    return approval


def reserve_or_replay(reservation: Reservation, *, pending_directory: Path = state.PENDING_DIR,
                      lease_directory: Path = LEASE_DIR) -> str:
    """Reserve one host-section or return the exact same change as a replay."""
    _validate_reservation(reservation)
    _private_root_directory(lease_directory)
    lease = lease_directory / (reservation.target + "--" + reservation.control + ".json")
    record = {"version": 1, "change_id": reservation.change_id,
              "request_id": reservation.request_id, "approval_id": reservation.approval_id}
    try:
        _write_exclusive(lease, (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"))
    except FileExistsError:
        try:
            existing = json.loads(lease.read_text(encoding="ascii"), object_pairs_hook=_unique_object)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise SupervisorRejected("existing host-section reservation is ambiguous") from exc
        if type(existing) is dict and existing == record:
            return "replay"
        raise SupervisorRejected("host-section already reserved")
    try:
        state.reserve(state.pending_record(
            reservation.request_id, reservation.boot_id, reservation.target,
            reservation.control, reservation.release_digest, job_id=reservation.job_id,
            approval_id=reservation.approval_id), pending_directory)
    except Exception:
        # The lease intentionally remains a durable blocker for reconciliation.
        raise
    return "reserved"


def _validate_reservation(reservation: Reservation) -> None:
    _uuid(reservation.request_id, "request id")
    _uuid(reservation.boot_id, "boot id")
    _uuid(reservation.approval_id, "approval id")
    _identifier(reservation.job_id, "job id")
    _identifier(reservation.target, "target")
    _identifier(reservation.control, "control")
    _identifier(reservation.change_id, "change id")
    _digest(reservation.release_digest, "release digest")


def claim_before_worker(reservation: Reservation, binding: dict, *,
                        pending_directory: Path = state.PENDING_DIR,
                        claim_directory: Path = launch_claim.CLAIM_DIR) -> None:
    """Delegate the atomic O_EXCL claim to the existing durable primitive."""
    _validate_reservation(reservation)
    launch_claim.claim(reservation.request_id, binding, pending_directory=pending_directory,
                       claim_directory=claim_directory)


def validate_prestart(*, request_id: str, invocation_id: str, unit: str,
                      show_invocation_id: str, pending_directory: Path = state.PENDING_DIR,
                      claim_directory: Path = launch_claim.CLAIM_DIR) -> None:
    """Reject a substituted unit or InvocationID before a worker can start."""
    expected = state.read_pending(request_id, pending_directory)
    binding = launch_claim.read_claim(request_id, pending_directory=pending_directory,
                                      claim_directory=claim_directory)
    if (expected["unit"] != unit or binding["invocation_id"] != invocation_id
            or show_invocation_id != invocation_id):
        raise SupervisorRejected("systemd invocation identity mismatch")
    retained_observation._validate_binding(expected, binding)


def reconcile(*, request_id: str, properties: dict, cgroup_events: str,
              boot_id: str, pending_directory: Path = state.PENDING_DIR,
              claim_directory: Path = launch_claim.CLAIM_DIR) -> str:
    """Return retained terminal evidence or ambiguous; never remove a blocker."""
    expected = state.read_pending(request_id, pending_directory)
    binding = launch_claim.read_claim(request_id, pending_directory=pending_directory,
                                      claim_directory=claim_directory)
    try:
        terminal = retained_observation.classify(expected, binding, properties, boot_id)
        empty = state.terminal_and_empty(expected, properties,
                                         properties.get("ControlGroup"), cgroup_events, boot_id)
    except state.Blocked:
        return "ambiguous"
    return terminal if empty else "ambiguous"
