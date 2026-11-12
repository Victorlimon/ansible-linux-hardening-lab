"""Inert supervisor foundations; no launcher, approval, CLI or marker deletion.

Callers must serialize reservation/observation with deployment and job locks.
Observations must come from trusted, same-boot systemd/cgroup-v2 collectors.
The predicate below is necessary evidence, NOT authority to retire a marker:
launch/restart exclusion and fresh, identity-bound observations remain required.
"""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import stat
import uuid


PENDING_DIR = Path("/var/lib/ansible-wazuh/pending-executions")
IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}\Z")
MAX_MARKER = 4096


class Blocked(ValueError):
    """Missing or untrusted evidence must preserve the pending execution."""


def canonical_uuid(value):
    if type(value) is not str:
        raise Blocked("canonical UUID required")
    try:
        parsed = uuid.UUID(value)
    except ValueError as exc:
        raise Blocked("canonical UUID required") from exc
    if str(parsed) != value or parsed.int == 0:
        raise Blocked("canonical nonzero UUID required")
    return parsed


def unit_name(request_id):
    return "ansible-wazuh@" + canonical_uuid(request_id).hex + ".service"


def pending_record(request_id, boot_id, target, control, release_digest, *,
                   job_id=None, approval_id=None):
    canonical_uuid(boot_id)
    for value in (target, control):
        if type(value) is not str or not IDENTIFIER.fullmatch(value):
            raise Blocked("invalid target or control identifier")
    if (type(release_digest) is not str
            or not re.fullmatch(r"[0-9a-f]{64}", release_digest)):
        raise Blocked("release digest required")
    record = {"version": 1, "request_id": request_id, "boot_id": boot_id,
            "unit": unit_name(request_id), "target": target, "control": control,
            "release_digest": release_digest}
    if job_id is not None or approval_id is not None:
        canonical_uuid(approval_id)
        if type(job_id) is not str or not IDENTIFIER.fullmatch(job_id):
            raise Blocked("invalid job identity")
        record.update(version=2, job_id=job_id, approval_id=approval_id)
    return record


def validate_record(record):
    try:
        additional = ({key: record[key] for key in ("job_id", "approval_id")}
                      if record.get("version") == 2 else {})
        expected = pending_record(*(record[key] for key in
            ("request_id", "boot_id", "target", "control", "release_digest")), **additional)
        if type(record) is not dict or type(record.get("version")) is not int or record != expected:
            raise Blocked("invalid pending record")
    except (AttributeError, KeyError, TypeError) as exc:
        raise Blocked("invalid pending record") from exc


@contextmanager
def private_directory(path):
    """Walk directory descriptors: no symlink traversal or writable ancestors."""
    if os.name != "posix" or os.getuid() != 0 or os.geteuid() != 0:
        raise Blocked("POSIX root required")
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise Blocked("absolute canonical directory required")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open("/", flags)
    try:
        for part in (*path.parts[1:], None):
            metadata = os.fstat(fd)
            mask = 0o077 if part is None else 0o022
            if (metadata.st_uid != 0 or not stat.S_ISDIR(metadata.st_mode)
                    or metadata.st_mode & mask):
                raise Blocked("root-private directory and trusted ancestors required")
            if part is not None:
                child = os.open(part, flags, dir_fd=fd)
                os.close(fd)
                fd = child
        yield fd
    finally:
        os.close(fd)


def has_pending(directory=PENDING_DIR):
    """Every directory entry blocks, including damaged/unknown reservations."""
    with private_directory(directory) as fd:
        return bool(os.listdir(fd))


def reserve(record, directory=PENDING_DIR):
    """Exclusive durable reservation; a failed write deliberately leaves a blocker.

    Return only after file and directory fsync. Never overwrite, repair or unlink
    an existing reservation. Provisioning the directory is an administrator task.
    """
    validate_record(record)
    _create_marker(record, record["request_id"], directory)


def _create_marker(record, request_id, directory):
    """Shared root-private JSON storage; callers validate their exact schemas."""
    canonical_uuid(request_id)
    data = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    if len(data) > MAX_MARKER:
        raise Blocked("marker exceeds size limit")
    with private_directory(directory) as directory_fd:
        fd = os.open(request_id + ".json",
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=directory_fd)
        try:
            # Persist the blocker before its content; partial writes fail closed.
            os.fsync(directory_fd)
            while data:
                written = os.write(fd, data)
                if written <= 0:
                    raise Blocked("incomplete pending marker write")
                data = data[written:]
            os.fsync(fd)
            os.fsync(directory_fd)
        finally:
            os.close(fd)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Blocked("duplicate marker key")
        result[key] = value
    return result


def read_pending(request_id, directory=PENDING_DIR):
    record = _read_marker(request_id, directory)
    validate_record(record)
    if record["request_id"] != request_id:
        raise Blocked("marker identity mismatch")
    return record


def _read_marker(request_id, directory):
    """Read private JSON without trusting its schema or authorizing any action."""
    canonical_uuid(request_id)
    with private_directory(directory) as directory_fd:
        fd = os.open(request_id + ".json", os.O_RDONLY | os.O_NOFOLLOW
                     | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory_fd)
        try:
            metadata = os.fstat(fd)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
                    or metadata.st_mode & 0o077 or metadata.st_nlink != 1
                    or metadata.st_size > MAX_MARKER):
                raise Blocked("untrusted pending marker")
            data = os.read(fd, MAX_MARKER + 1)
            if len(data) != metadata.st_size or not data.endswith(b"\n"):
                raise Blocked("incomplete pending marker")
            try:
                record = json.loads(data, object_pairs_hook=_unique_object)
            except (ValueError, UnicodeDecodeError) as exc:
                raise Blocked("invalid pending marker") from exc
            return record
        finally:
            os.close(fd)


def terminal_and_empty(record, properties, cgroup_path, cgroup_events, boot_id):
    """Conservative pure predicate, never cleanup authorization or success status.

    Missing/collected units, missing cgroups and reboot mismatches remain blocked.
    cgroup.events populated=0 covers descendants; an empty cgroup.procs does not.
    """
    try:
        validate_record(record)
        if boot_id != record["boot_id"] or type(properties) is not dict:
            return False
        expected = {"Id": record["unit"], "LoadState": "loaded", "Type": "exec",
                    "KillMode": "control-group", "Restart": "no", "MainPID": "0",
                    "ControlPID": "0", "ControlGroup": "/system.slice/" + record["unit"]}
        if any(properties.get(key) != value for key, value in expected.items()):
            return False
        if (properties.get("ActiveState"), properties.get("SubState")) not in (
                ("inactive", "dead"), ("failed", "failed")):
            return False
        invocation = properties.get("InvocationID", "")
        exited = properties.get("ExecMainExitTimestampMonotonic", "")
        if (type(invocation) is not str or not re.fullmatch(r"[0-9a-f]{32}", invocation)
                or int(invocation, 16) == 0 or type(exited) is not str
                or not re.fullmatch(r"[1-9][0-9]*", exited)):
            return False
        if cgroup_path != expected["ControlGroup"] or type(cgroup_events) is not str:
            return False
        fields = {}
        for line in cgroup_events.splitlines():
            key, value = line.split()
            if key in fields or value not in ("0", "1"):
                return False
            fields[key] = value
        return fields.get("populated") == "0"
    except (Blocked, ValueError, TypeError):
        return False
