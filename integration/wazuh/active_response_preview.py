#!/usr/bin/python3
"""Wazuh Active Response adapter for bounded read-only laboratory previews."""

from __future__ import annotations

import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone


MAX_REQUEST_BYTES = 65536
MAX_CHILD_OUTPUT_BYTES = 16384
TIMEOUT_SECONDS = 630
RUNNER = Path("/home/vagrant/ansible/integration/wazuh/local_executor.py")
PYTHON = "/usr/bin/python3"
EVENT_LOG = Path("/var/log/ansible-wazuh-preview.jsonl")
SCRIPT_PATH = Path("/var/ossec/active-response/bin/ansible-preview")
ALLOWED_HOSTS = frozenset(("ubuntu24", "debian12"))
ALLOWED_SECTIONS = frozenset(("cron_hourly", "cron_daily"))
UNKNOWN_EVENT_PAIR = ("unknown", "unknown")


class RejectedRequest(ValueError):
    pass


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RejectedRequest("duplicate JSON key")
        result[key] = value
    return result


def parse_request(line: bytes) -> tuple[str, str]:
    if len(line) > MAX_REQUEST_BYTES or not line.endswith(b"\n"):
        raise RejectedRequest("request size or framing invalid")
    try:
        message = json.loads(line.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RejectedRequest("invalid JSON") from exc
    if not isinstance(message, dict) or type(message.get("version")) is not int or message["version"] != 1:
        raise RejectedRequest("unsupported protocol version")
    origin = message.get("origin")
    if not isinstance(origin, dict) or origin.get("module") != "wazuh-execd":
        raise RejectedRequest("unexpected protocol origin")
    if message.get("command") != "add":
        raise RejectedRequest("unsupported command")
    parameters = message.get("parameters")
    if not isinstance(parameters, dict):
        raise RejectedRequest("host or section not allowed")
    extra_args = parameters.get("extra_args")
    if (not isinstance(extra_args, list) or len(extra_args) != 2
            or not all(type(item) is str for item in extra_args)):
        raise RejectedRequest("arguments must be strings")
    host, section = extra_args
    if host not in ALLOWED_HOSTS or section not in ALLOWED_SECTIONS:
        raise RejectedRequest("host or section not allowed")
    return host, section


def secure_entrypoint() -> None:
    if sys.platform != "linux" or os.geteuid() != 0 or os.getuid() != 0:
        raise OSError("root execution required")
    actual = Path(__file__).resolve()
    if actual != SCRIPT_PATH:
        raise OSError("adapter must be installed at the fixed path")
    for path in (actual, actual.parent):
        metadata = path.stat()
        if metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise OSError("adapter path must be root-owned and not writable by others")
    if not stat.S_ISREG(actual.stat().st_mode):
        raise OSError("adapter is not a regular file")


def drop_to_vagrant() -> None:
    import pwd

    account = pwd.getpwnam("vagrant")
    os.initgroups(account.pw_name, account.pw_gid)
    os.setgid(account.pw_gid)
    os.setuid(account.pw_uid)


def launch_preview(host: str, section: str) -> tuple[int, bytes, bool]:
    if not RUNNER.is_file() or not os.access(PYTHON, os.X_OK):
        raise OSError("fixed runner or system Python unavailable")
    command = [PYTHON, "-B", str(RUNNER), "--host", host,
               "--section", section]
    environment = {"HOME": "/home/vagrant", "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    process = subprocess.Popen(command, shell=False, cwd="/home/vagrant/ansible",
                               env=environment, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               start_new_session=True, preexec_fn=drop_to_vagrant)
    captured = bytearray()
    truncated = False
    deadline = time.monotonic() + TIMEOUT_SECONDS
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, TIMEOUT_SECONDS)
                for key, _ in selector.select(timeout=remaining):
                    chunk = os.read(key.fd, 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    space = MAX_CHILD_OUTPUT_BYTES - len(captured)
                    captured.extend(chunk[:space])
                    truncated |= len(chunk) > space
        return process.wait(timeout=max(0, deadline - time.monotonic())), bytes(captured), truncated
    except (OSError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise
    finally:
        process.stdout.close()


def terminal_status(return_code: int, output: bytes, truncated: bool,
                    host: str, section: str) -> tuple[str, str | None]:
    if truncated:
        return "failed", None
    try:
        events = [json.loads(line) for line in output.splitlines()]
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "failed", None
    if not events or not all(isinstance(item, dict) for item in events):
        return "failed", None
    terminal = events[-1]
    if terminal.get("mode") != "check" or terminal.get("host") != host or terminal.get("section") != section:
        return "failed", None
    runner_id = terminal.get("request_id")
    try:
        runner_id = str(uuid.UUID(runner_id))
    except (ValueError, TypeError, AttributeError):
        return "failed", None
    status = terminal.get("status")
    if return_code == 0 and status == "completed":
        return "completed", runner_id
    if return_code == 2 and status == "rejected":
        return "rejected", runner_id
    return "failed", runner_id


def record(status: str, request_id: str, *, host: str, section: str,
           runner_id: str | None = None) -> None:
    event = {"timestamp": datetime.now(timezone.utc).isoformat(), "source": "ansible-wazuh-preview",
             "request_id": request_id, "status": status, "host": host,
             "section": section, "mode": "check"}
    if runner_id:
        event["runner_request_id"] = runner_id
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW
    fd = os.open(EVENT_LOG, flags, 0o600)
    try:
        metadata = os.fstat(fd)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
                or metadata.st_mode & 0o077 or metadata.st_nlink != 1):
            raise OSError("event log must be private and root-owned")
        os.write(fd, (json.dumps(event, separators=(",", ":")) + "\n").encode("utf-8"))
    finally:
        os.close(fd)


def main() -> int:
    request_id = str(uuid.uuid4())
    pair = UNKNOWN_EVENT_PAIR
    try:
        secure_entrypoint()
        line = sys.stdin.buffer.readline(MAX_REQUEST_BYTES + 1)
        pair = parse_request(line)
        record("accepted", request_id, host=pair[0], section=pair[1])
        return_code, output, truncated = launch_preview(*pair)
        status, runner_id = terminal_status(return_code, output, truncated, *pair)
        record(status, request_id, host=pair[0], section=pair[1], runner_id=runner_id)
        return 0 if status == "completed" else 1
    except RejectedRequest:
        try:
            record("rejected", request_id, host=pair[0], section=pair[1])
        except OSError:
            pass
        return 2
    except (OSError, subprocess.SubprocessError, KeyError):
        try:
            record("failed", request_id, host=pair[0], section=pair[1])
        except OSError:
            pass
        return 1


if __name__ == "__main__":
    sys.exit(main())
