"""Read-only, source-only observation; never authority to launch or retire work.

Requires trusted Linux root execution in the system manager's mount/PID namespace.
Caller must hold launch/restart/deployment exclusion throughout observation and
use. Bracketing reads detect drift, not ABA or changes after return. No gateway
imports this module, and there is deliberately no CLI or cleanup API.
"""

from contextlib import contextmanager
import ctypes
import os
from pathlib import PurePosixPath
import re
import selectors
import stat
import subprocess
import sys
import time

from integration.wazuh import execution_state as state


PROPERTIES = ("Id", "LoadState", "Type", "KillMode", "Restart", "MainPID",
              "ControlPID", "ControlGroup", "ActiveState", "SubState",
              "InvocationID", "ExecMainExitTimestampMonotonic")
BOOT_FILE = "/proc/sys/kernel/random/boot_id"
CGROUP_ROOT = "/sys/fs/cgroup"
SYSTEMCTL = "/usr/bin/systemctl"
MAX_OUTPUT = 4096
TOTAL_SECONDS = 5.0
COMMAND_SECONDS = 2.0
ENVIRONMENT = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "SYSTEMD_COLORS": "0",
               "SYSTEMD_PAGER": "cat"}


def _require_root():
    if (sys.platform != "linux" or os.getuid() != 0 or os.geteuid() != 0):
        raise state.Blocked("Linux real/effective root required")


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise state.Blocked("observation timeout")
    return remaining


def _metadata(fd, directory=False):
    info = os.fstat(fd)
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if (info.st_uid != 0 or info.st_mode & 0o6022
            or not expected_type(info.st_mode)):
        raise state.Blocked("untrusted evidence ownership, mode or type")
    return info


@contextmanager
def _trusted_file(path):
    """Open root-owned, non-writable ancestry without following any symlink."""
    parsed = PurePosixPath(path)
    if not parsed.is_absolute() or str(parsed) != path or ".." in parsed.parts:
        raise state.Blocked("canonical absolute evidence path required")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    fd = os.open("/", flags | os.O_DIRECTORY)
    try:
        _metadata(fd, directory=True)
        for index, part in enumerate(parsed.parts[1:]):
            directory = index < len(parsed.parts) - 2
            child = os.open(part, flags | (os.O_DIRECTORY if directory else 0), dir_fd=fd)
            os.close(fd)
            fd = child
            _metadata(fd, directory=directory)
        yield fd
    finally:
        os.close(fd)


def _filesystem(fd, magic):
    """Check the opened Linux descriptor, not a racy path/mount-table guess."""
    # Linux statfs starts with a native long f_type; reserve ample aligned space.
    buffer = (ctypes.c_long * 64)()
    libc = ctypes.CDLL(None, use_errno=True)
    call = libc.fstatfs
    call.argtypes = (ctypes.c_int, ctypes.c_void_p)
    call.restype = ctypes.c_int
    if call(fd, ctypes.byref(buffer)) != 0 or buffer[0] != magic:
        raise state.Blocked("unexpected evidence filesystem")


def _read_kernel_file(path, magic, deadline):
    _remaining(deadline)
    with _trusted_file(path) as fd:
        _filesystem(fd, magic)
        before = os.fstat(fd)
        data = os.read(fd, MAX_OUTPUT + 1)
        after = os.fstat(fd)
        identity = (before.st_dev, before.st_ino)
        if identity != (after.st_dev, after.st_ino) or len(data) > MAX_OUTPUT:
            raise state.Blocked("unstable or oversized kernel evidence")
    _remaining(deadline)
    try:
        text = data.decode("ascii")
    except UnicodeError as exc:
        raise state.Blocked("non-ASCII kernel evidence") from exc
    if not text.endswith("\n") or "\x00" in text:
        raise state.Blocked("incomplete kernel evidence")
    return text, identity


def _boot(deadline):
    text, _ = _read_kernel_file(BOOT_FILE, 0x9FA0, deadline)  # procfs
    value = text[:-1]
    state.canonical_uuid(value)
    return value


def _run_show(unit, deadline, properties=PROPERTIES):
    """Only fixed local systemctl show; bounded stdout, no inherited bus/env."""
    command_deadline = min(deadline, time.monotonic() + COMMAND_SECONDS)
    with _trusted_file(SYSTEMCTL) as executable:
        if not os.fstat(executable).st_mode & 0o111:
            raise state.Blocked("systemctl is not executable")
        argv = [f"/proc/self/fd/{executable}", "--system", "--no-pager", "show", "--all",
                "--property=" + ",".join(properties), "--", unit]
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, env=ENVIRONMENT, cwd="/",
                                   close_fds=True, pass_fds=(executable,))
    try:
        output = bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                if not selector.select(_remaining(command_deadline)):
                    raise state.Blocked("systemctl observation timeout")
                chunk = os.read(process.stdout.fileno(), MAX_OUTPUT + 1 - len(output))
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > MAX_OUTPUT:
                    raise state.Blocked("oversized systemctl observation")
        if process.wait(timeout=_remaining(command_deadline)) != 0:
            raise state.Blocked("systemctl observation failed")
        return bytes(output)
    finally:
        if process.poll() is None:
            process.kill()  # Only the read-only systemctl client, never the unit.
            process.wait(timeout=COMMAND_SECONDS)
        process.stdout.close()


def _parse_fields(data, properties):
    if type(data) is not bytes or len(data) > MAX_OUTPUT or not data.endswith(b"\n"):
        raise state.Blocked("incomplete or oversized systemctl properties")
    try:
        text = data.decode("ascii")
    except UnicodeError as exc:
        raise state.Blocked("non-ASCII properties") from exc
    if any((ord(char) < 32 and char != "\n") or ord(char) == 127 for char in text):
        raise state.Blocked("control character in systemctl properties")
    result = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if (not separator or key not in properties or key in result
                or any(ord(char) < 32 or ord(char) == 127 for char in value)):
            raise state.Blocked("malformed or duplicate systemctl property")
        result[key] = value
    if set(result) != set(properties):
        raise state.Blocked("missing systemctl properties")
    return result


def _parse_properties(data, record):
    result = _parse_fields(data, PROPERTIES)
    required = {"Id": record["unit"], "LoadState": "loaded", "Type": "exec",
                "KillMode": "control-group", "Restart": "no",
                "ControlGroup": "/system.slice/" + record["unit"]}
    if any(result[key] != value for key, value in required.items()):
        raise state.Blocked("unit identity or supervision contract mismatch")
    for key in ("MainPID", "ControlPID", "ExecMainExitTimestampMonotonic"):
        if not re.fullmatch(r"0|[1-9][0-9]{0,19}", result[key]):
            raise state.Blocked("invalid numeric systemctl property")
    if (not re.fullmatch(r"[0-9a-f]{32}", result["InvocationID"])
            or int(result["InvocationID"], 16) == 0):
        raise state.Blocked("missing invocation identity")
    if not all(re.fullmatch(r"[a-z][a-z-]{0,31}", result[key])
               for key in ("ActiveState", "SubState")):
        raise state.Blocked("invalid unit state")
    return result


def _events(text):
    fields = {}
    for line in text.splitlines():
        parts = line.split()
        if (len(parts) != 2 or parts[0] not in ("populated", "frozen")
                or parts[0] in fields or parts[1] not in ("0", "1")):
            raise state.Blocked("malformed cgroup events")
        fields[parts[0]] = parts[1]
    if "populated" not in fields:
        raise state.Blocked("missing hierarchical populated evidence")


def collect(record):
    """Return bracketed evidence or Blocked; no absent-equals-empty fallback.

    A dictionary passed by a caller is not authenticated by this function: use a
    trusted pending record. The returned dictionary is not a retirement token.
    """
    state.validate_record(record)
    record = dict(record)
    _require_root()
    started = time.monotonic()
    deadline = started + TOTAL_SECONDS
    try:
        boot = _boot(deadline)
        if boot != record["boot_id"]:
            raise state.Blocked("pending execution belongs to another boot")
        before = _parse_properties(_run_show(record["unit"], deadline), record)
        path = before["ControlGroup"]
        filename = CGROUP_ROOT + path + "/cgroup.events"
        events, identity = _read_kernel_file(filename, 0x63677270, deadline)
        _events(events)
        after = _parse_properties(_run_show(record["unit"], deadline), record)
        final_events, final_identity = _read_kernel_file(filename, 0x63677270, deadline)
        if (before != after or events != final_events or identity != final_identity
                or _boot(deadline) != boot):
            raise state.Blocked("observation changed during collection")
        _remaining(deadline)
        return {"properties": before, "boot_id": boot, "cgroup_path": path,
                "cgroup_events": events, "started_monotonic": started,
                "finished_monotonic": time.monotonic()}
    except (OSError, subprocess.SubprocessError, AttributeError) as exc:
        # Never return partial evidence or expose raw command/error output.
        raise state.Blocked("local observation unavailable") from exc
