"""Bounded, Wazuh-independent launcher for laboratory CIS previews."""

from __future__ import annotations

import argparse
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
from contextlib import contextmanager
from datetime import datetime, timezone
from types import MappingProxyType


REPO_ROOT = Path(__file__).resolve().parents[2]
ANSIBLE_DIR = REPO_ROOT / "ansible"
INVENTORY = ANSIBLE_DIR / "inventories/local/hosts.yml"
HOSTS = MappingProxyType({
    "ubuntu24": (ANSIBLE_DIR / "playbooks/hardening/cis_ubuntu_2404.yml",
                 ("cis_ubuntu_2404_remediation_enabled=true",)),
    "debian12": (ANSIBLE_DIR / "playbooks/hardening/cis_debian_12.yml",
                 ("cis_debian_12_remediation_enabled=true",
                  "cis_debian_12_canary_confirmed=true")),
})
CONTROLS = MappingProxyType({
    "cron_hourly": "cis_2_4_1_3",
    "cron_daily": "cis_2_4_1_4",
})
TIMEOUT_SECONDS = 600
TRUSTED_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
LAB_REPO_ROOT = Path("/home/vagrant/ansible")
LAB_ANSIBLE_BIN = Path("/home/vagrant/.venvs/ansible-cis/bin")
MAX_OUTPUT_BYTES = 1024 * 1024


def executable_path() -> str:
    """Use the documented lab venv only from its mounted control-node checkout."""
    if sys.platform != "linux":
        return TRUSTED_PATH
    import pwd

    if (os.getuid() != 0
            and pwd.getpwuid(os.getuid()).pw_name == "vagrant"
            and Path.home() == Path("/home/vagrant")
            and REPO_ROOT == LAB_REPO_ROOT
            and (LAB_ANSIBLE_BIN / "ansible-playbook").is_file()
            and os.access(LAB_ANSIBLE_BIN / "ansible-playbook", os.X_OK)):
        return f"{LAB_ANSIBLE_BIN}:{TRUSTED_PATH}"
    return TRUSTED_PATH


def event(request_id: str, status: str, *, host: str, section: str, mode: str,
          detail: str | None = None,
          output_file: Path | None = None, output_truncated: bool = False) -> None:
    record = {
        "request_id": request_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "host": host,
        "section": section,
        "mode": mode,
    }
    if detail is not None:
        record["detail"] = detail
    if output_file is not None:
        record["output_file"] = str(output_file)
        record["output_truncated"] = output_truncated
    print(json.dumps(record, separators=(",", ":")), flush=True)


def state_directory() -> Path:
    state_dir = Path.home() / ".local/state/ansible-hardening-executor"
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = state_dir.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
        raise OSError("private state directory required")
    return state_dir


@contextmanager
def host_lock(host: str):
    """Hold a Linux flock until the launcher and its Ansible child both exit."""
    if sys.platform != "linux":
        raise OSError("Linux is required")
    lock_path = state_directory() / f"{host}.lock"
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        import fcntl

        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise BlockingIOError("host is already running") from exc
        yield fd
    finally:
        os.close(fd)


@contextmanager
def output_capture(request_id: str):
    path = state_directory() / f"{request_id}.ansible.log"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        yield path, stream


def command(host: str, section: str, apply: bool = False) -> list[str]:
    if apply:
        raise ValueError("direct apply is disabled")
    playbook, remediation_gates = HOSTS[host]
    args = [
        "ansible-playbook", str(playbook), "-i", str(INVENTORY),
        "--limit", host, "--tags", CONTROLS[section],
    ]
    for gate in remediation_gates:
        args.extend(("-e", gate))
    args.extend(("--check", "--diff"))
    return args


def write_bounded(stream, chunk: bytes, written: int) -> tuple[int, bool]:
    available = MAX_OUTPUT_BYTES - written
    if available > 0:
        saved = chunk[:available]
        stream.write(saved)
        written += len(saved)
    return written, len(chunk) > available


def run_process(args: list[str], lock_fd: int, output_stream) -> tuple[int, bool]:
    # Keep raw output in a private bounded file, never in the JSON event stream.
    # Do not inherit ANSIBLE_* overrides, SSH_AUTH_SOCK, or callback/plugin
    # paths from the caller. The lab inventory intentionally names its key.
    environment = {
        "HOME": str(Path.home()),
        "PATH": executable_path(),
        "LANG": "C.UTF-8",
        "ANSIBLE_CONFIG": str(ANSIBLE_DIR / "ansible.cfg"),
        "ANSIBLE_NOCOLOR": "1",
    }
    proc = subprocess.Popen(
        args, cwd=ANSIBLE_DIR, shell=False,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, start_new_session=True,
        pass_fds=(lock_fd,), env=environment,
    )
    truncated = False
    written = 0
    deadline = time.monotonic() + TIMEOUT_SECONDS
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(args[0], TIMEOUT_SECONDS)
                for key, _ in selector.select(timeout=remaining):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    written, overflow = write_bounded(output_stream, chunk, written)
                    truncated |= overflow
        remaining = max(0, deadline - time.monotonic())
        return proc.wait(timeout=remaining), truncated
    except (subprocess.TimeoutExpired, OSError):
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
        raise
    finally:
        if proc.stdout is not None:
            proc.stdout.close()


def execute(host: str, section: str, apply: bool = False) -> int:
    request_id = str(uuid.uuid4())
    mode = "apply" if apply else "check"
    def emit(status: str, **kwargs) -> None:
        event(request_id, status, host=host, section=section, mode=mode, **kwargs)

    if apply:
        emit("rejected", detail="direct apply is disabled")
        return 2
    if host not in HOSTS or section not in CONTROLS:
        emit("rejected", detail="host or section not allowed")
        return 2
    if not INVENTORY.is_file() or not HOSTS[host][0].is_file():
        emit("failed", detail="required repository file missing")
        return 1
    try:
        with host_lock(host) as lock_fd:
            emit("accepted")
            try:
                with output_capture(request_id) as (output_file, output_stream):
                    emit("started")
                    try:
                        return_code, truncated = run_process(command(host, section, apply), lock_fd, output_stream)
                    except subprocess.TimeoutExpired:
                        emit("failed", detail="timeout", output_file=output_file)
                        return 1
                    except OSError:
                        emit("failed", detail="launcher error", output_file=output_file)
                        return 1
            except OSError:
                emit("failed", detail="output capture unavailable")
                return 1
            if return_code != 0:
                emit("failed", detail=f"ansible exit code {return_code}",
                     output_file=output_file, output_truncated=truncated)
                return 1
            emit("completed", output_file=output_file, output_truncated=truncated)
            return 0
    except BlockingIOError:
        emit("rejected", detail="host already running")
        return 2
    except OSError:
        emit("failed", detail="lock unavailable")
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, help="Exact inventory alias")
    parser.add_argument("--section", required=True, help="Approved control selector")
    parser.add_argument("--apply", action="store_true", help="Rejected legacy option; use the separately approved managed job workflow")
    args = parser.parse_args()
    return execute(args.host, args.section, args.apply)


if __name__ == "__main__":
    sys.exit(main())
