#!/usr/bin/python3 -I
"""Stage only reviewed Ansible Python packages in a new sealed release.

This is an administrator-run preparation tool, not a Wazuh entrypoint. It
never activates a release or launches a playbook against managed hosts.
"""

from __future__ import annotations

import argparse
import ast
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile

import hashlib


GATEWAY_PATH = Path(__file__).with_name("managed_job.py")

PACKAGES = ("ansible", "yaml", "jinja2", "markupsafe", "cryptography",
            "packaging", "resolvelib")
METADATA_PACKAGES = ("ansible-core", "jinja2", "pyyaml", "markupsafe",
                     "cryptography", "packaging", "resolvelib")
BOOTSTRAP = Path(__file__).with_name("runtime_bootstrap.py")
MANAGED_HELPERS = (
    "managed_profiles.py", "managed_supervisor.py", "execution_state.py",
    "launch_claim.py", "retained_observation.py", "execution_observation.py",
    "evidence_reconcile.py",
)
LAB_CATALOG = Path(__file__).with_name("config") / "profiles.lab.json.example"
REQUIRED_CORE = "2.21.2"
SYNTAX_CHECK_TIMEOUT = 420
INVENTORY_OUTPUT_LIMIT = 1024 * 1024
VALIDATION_PHASES = frozenset({
    "playbook_preflight", "playbook_version", "inventory_preflight",
    "inventory_version", "inventory_graph",
    "syntax_debian_preflight", "syntax_ubuntu_audit", "syntax_debian_audit",
    "syntax_ubuntu_verify", "syntax_debian_verify",
    "syntax_ubuntu_hardening", "syntax_debian_hardening",
})


def trusted_source(path: Path, *, inspect_members: bool = True) -> None:
    for item in (path, *path.parents):
        metadata = item.lstat()
        if metadata.st_uid != 0 or metadata.st_mode & 0o022 or stat.S_ISLNK(metadata.st_mode):
            raise ValueError("untrusted package source")
    if not inspect_members:
        return
    for current, directories, files in os.walk(path, followlinks=False):
        for name in directories + files:
            item = Path(current) / name
            metadata = item.lstat()
            if (metadata.st_uid != 0 or metadata.st_mode & 0o022
                    or not (stat.S_ISDIR(metadata.st_mode)
                            or stat.S_ISREG(metadata.st_mode))
                    or (stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1)):
                raise ValueError("untrusted package member")


def normalize_copied_runtime(runtime: Path) -> None:
    """Make only the copied runtime traversable under a restrictive root umask."""
    for current, directories, files in os.walk(runtime, followlinks=False):
        for item in [Path(current), *(Path(current) / name for name in directories)]:
            metadata = item.lstat()
            if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0
                    or metadata.st_mode & 0o022):
                raise ValueError("untrusted copied runtime directory")
            item.chmod(0o755)
        for name in files:
            item = Path(current) / name
            metadata = item.lstat()
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
                    or metadata.st_mode & 0o022 or metadata.st_nlink != 1):
                raise ValueError("untrusted copied runtime file")
            item.chmod(0o644)


def staging_service(gateway, release: Path, payload: Path) -> tuple[str, dict]:
    """Require root-local policy and service scratch before validating a runtime."""
    import pwd
    policy_path = release / "policy.json"
    try:
        raw = gateway.trusted_file(policy_path)
        if policy_path.stat().st_mode & 0o077:
            raise ValueError("root-private staging policy required")
        policy = json.loads(raw, object_pairs_hook=gateway.unique_object)
        if (type(policy) is not dict or policy.get("version") != 2
                or policy.get("release_id") != release.name
                or policy.get("ansible_root") != str(payload / "ansible")
                or policy.get("ansible_bin_dir") != str(payload / "runtime" / "bin")
                or policy.get("inventory") != str(payload / "inventory" / "hosts.yml")
                or type(policy.get("service_user")) is not str
                or type(policy.get("targets")) is not dict):
            raise ValueError("staging policy does not match candidate release")
        account = pwd.getpwnam(policy["service_user"])
        if account.pw_uid == 0:
            raise ValueError("non-root service account required")
        gateway.service_directory(gateway.LOCAL_TEMP, account.pw_uid)
        gateway.trusted_file(payload / "inventory" / "hosts.yml")
        gateway.trusted_file(payload / "ansible" / "ansible.cfg")
        for _, playbook, _ in gateway.JOBS.values():
            gateway.trusted_file(payload / "ansible" / "playbooks" / playbook)
        return account.pw_name, policy
    except (OSError, KeyError, TypeError, json.JSONDecodeError, gateway.Reject) as exc:
        raise ValueError("staging policy, service account, scratch or inventory unavailable") from exc


def load_gateway():
    # Importing the gateway executes Python code. Check the administrator's
    # source directory before importing it, not after a release was modified.
    for path in (Path(__file__), GATEWAY_PATH, BOOTSTRAP):
        trusted_source(path, inspect_members=False)
        if not path.is_file():
            raise ValueError("regular administrator-owned source required")
    spec = importlib.util.spec_from_file_location("managed_job", GATEWAY_PATH)
    if spec is None or spec.loader is None:
        raise ValueError("managed gateway source unavailable")
    gateway = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gateway)
    return gateway


def source_core_version(source: Path) -> str:
    """Reject the wrong package before copying it into a candidate release."""
    release = source / "ansible" / "release.py"
    trusted_source(release, inspect_members=False)
    for statement in ast.parse(release.read_text(encoding="utf-8")).body:
        if (isinstance(statement, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == "__version__"
                        for target in statement.targets)):
            value = ast.literal_eval(statement.value)
            if type(value) is str:
                return value
    raise ValueError("Ansible Core release version unavailable")


def require_source_core(source: Path) -> None:
    if source_core_version(source) != REQUIRED_CORE:
        raise ValueError("Ansible Core 2.21.2 source required")


def metadata_directories(source: Path) -> list[Path]:
    """Select exactly one trusted metadata directory for each bundled distribution."""
    selected: dict[str, Path] = {}
    for item in source.iterdir():
        if not item.name.endswith((".dist-info", ".egg-info")):
            continue
        stem = item.name.rsplit(".", 1)[0]
        if "-" not in stem:
            continue
        distribution = stem.rsplit("-", 1)[0]
        name = re.sub(r"[-_.]+", "-", distribution).lower()
        if name not in METADATA_PACKAGES:
            continue
        trusted_source(item)
        if not item.is_dir() or name in selected:
            raise ValueError("duplicate or invalid required package metadata")
        selected[name] = item
    if set(selected) != set(METADATA_PACKAGES):
        raise ValueError("required package metadata unavailable")
    return [selected[name] for name in METADATA_PACKAGES]


def run_bounded(arguments: list[str], *, cwd: Path, environment: dict[str, str],
                timeout: int, service_user: str, phase: str,
                capture_output: bool = False) -> tuple[bytes, bytes]:
    """Run trusted release code without a shell and terminate its process group on timeout."""
    if phase not in VALIDATION_PHASES:
        raise ValueError("invalid sealed runtime validation phase")
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        process = subprocess.Popen(arguments, cwd=cwd, env=environment, shell=False,
                                   stdin=subprocess.DEVNULL,
                                   stdout=stdout_file if capture_output else subprocess.DEVNULL,
                                   stderr=stderr_file if capture_output else subprocess.DEVNULL,
                                   start_new_session=True,
                                   preexec_fn=lambda: drop_validation_service(service_user))
        try:
            result = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise ValueError(f"sealed runtime validation timed out (phase: {phase})") from exc
        if result:
            raise ValueError(
                f"sealed runtime validation failed (phase: {phase}); inspect staging locally")
        if not capture_output:
            return b"", b""
        if (stdout_file.tell() > INVENTORY_OUTPUT_LIMIT
                or stderr_file.tell() > INVENTORY_OUTPUT_LIMIT):
            raise ValueError("sealed inventory output exceeds limit")
        stdout_file.seek(0)
        stderr_file.seek(0)
        return stdout_file.read(), stderr_file.read()


def check_inventory(gateway, payload: Path, service_user: str, policy: dict) -> None:
    """Reject an unreadable or mismatched inventory before any syntax checks."""
    root = payload / "ansible"
    inventory_file = payload / "inventory" / "hosts.yml"
    launcher = payload / "runtime" / "bin" / "ansible-inventory"
    output, warnings = run_bounded([str(launcher), "-i", str(inventory_file), "--list"],
                                   cwd=root, environment=gateway.runtime_environment(root),
                                   timeout=SYNTAX_CHECK_TIMEOUT, service_user=service_user,
                                   phase="inventory_graph", capture_output=True)
    if warnings or not output:
        raise ValueError("sealed inventory is empty or produced warnings")
    try:
        graph = json.loads(output.decode("utf-8"), object_pairs_hook=gateway.unique_object)
        if type(graph) is not dict or not graph:
            raise ValueError("sealed inventory graph unavailable")
        gateway.unique_target_addresses(policy, graph)
        if not policy["targets"]:
            raise ValueError("staging inventory has no policy targets")
        if any(type(target) is not dict or target.get("os") not in ("ubuntu24", "debian12")
               for target in policy["targets"].values()):
            raise ValueError("invalid staging target")
        for job_os, _, _ in gateway.JOBS.values():
            required_group = "ubuntu" if job_os == "ubuntu24" else "debian_12"
            for target in policy["targets"].values():
                if target.get("os") != job_os:
                    continue
                host = target.get("host")
                if (type(host) is not str or host in graph
                        or not gateway.group_contains(graph, required_group, host)):
                    raise ValueError("target absent from required inventory group")
                if job_os == "ubuntu24" and not gateway.group_contains(
                        graph, "ubuntu_2404", host):
                    raise ValueError("Ubuntu verify target absent from required inventory group")
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError,
            gateway.Reject) as exc:
        raise ValueError("sealed inventory graph invalid") from exc


def drop_validation_service(service_user: str) -> None:
    import pwd
    account = pwd.getpwnam(service_user)
    os.initgroups(account.pw_name, account.pw_gid)
    os.setgid(account.pw_gid)
    os.setuid(account.pw_uid)


def check_playbooks(gateway, payload: Path, service_user: str) -> None:
    """Parse every closed-catalog entrypoint; --syntax-check never targets hosts."""
    root = payload / "ansible"
    inventory = payload / "inventory" / "hosts.yml"
    launcher = payload / "runtime" / "bin" / "ansible-playbook"
    environment = gateway.runtime_environment(root)
    for job_id, (_, playbook, _) in gateway.JOBS.items():
        run_bounded([str(launcher), "--syntax-check", "-i", str(inventory),
                     str(root / "playbooks" / playbook)],
                    cwd=root, environment=environment, timeout=SYNTAX_CHECK_TIMEOUT,
                    service_user=service_user, phase="syntax_" + job_id)


def stage_managed(payload: Path, *, catalog_source: Path = LAB_CATALOG,
                  release_id: str | None = None) -> None:
    """Copy reviewed managed code and catalog into the not-yet-sealed payload."""
    source = Path(__file__).parent
    for name in MANAGED_HELPERS:
        candidate = source / name
        trusted_source(candidate, inspect_members=False)
        if not candidate.is_file():
            raise ValueError("managed helper unavailable")
    trusted_source(catalog_source, inspect_members=False)
    if not catalog_source.is_file():
        raise ValueError("managed profile catalog unavailable")
    try:
        catalog = json.loads(catalog_source.read_bytes())
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("managed profile catalog invalid") from exc
    if (type(catalog) is not dict or set(catalog) != {"releases"}
            or type(catalog["releases"]) is not dict
            or (release_id is not None and set(catalog["releases"]) != {release_id})):
        raise ValueError("managed profile catalog release mismatch")
    managed = payload / "managed"
    package = managed / "integration" / "wazuh"
    package.mkdir(parents=True, mode=0o755)
    for name in MANAGED_HELPERS:
        shutil.copy2(source / name, package / name)
    shutil.copy2(catalog_source, managed / "profiles.json")
    normalize_copied_runtime(managed)


def prepare(release_id: str, source: Path, *, catalog_source: Path = LAB_CATALOG) -> None:
    if os.getuid() != 0 or os.geteuid() != 0 or sys.platform != "linux":
        raise ValueError("root Linux preparation required")
    gateway = load_gateway()
    release = gateway.RELEASES_ROOT / gateway.identifier(release_id)
    payload = release / "payload"
    runtime = payload / "runtime"
    if not payload.is_dir() or runtime.exists() or runtime.is_symlink():
        raise ValueError("new payload without runtime required")
    trusted_source(payload)
    service_user, policy = staging_service(gateway, release, payload)
    trusted_source(source, inspect_members=False)
    if hashlib.sha256(BOOTSTRAP.read_bytes()).hexdigest() != gateway.BOOTSTRAP_SHA256:
        raise ValueError("bootstrap source differs from gateway pin")
    required = [source / name for name in PACKAGES]
    extensions = sorted(source.glob("_cffi_backend*.so"))
    metadata = metadata_directories(source)
    if any(not item.is_dir() for item in required) or len(extensions) != 1:
        raise ValueError("explicit Ansible package set unavailable")
    for item in required + extensions:
        trusted_source(item)
    require_source_core(source)
    stage_managed(payload, catalog_source=catalog_source, release_id=release_id)
    (runtime / "python").mkdir(parents=True, mode=0o755)
    (runtime / "bin").mkdir(mode=0o755)
    for item in required:
        shutil.copytree(item, runtime / "python" / item.name)
    for item in extensions:
        shutil.copy2(item, runtime / "python" / item.name)
    for item in metadata:
        destination = runtime / "python" / item.name
        if item.is_dir():
            shutil.copytree(item, destination)
        else:
            shutil.copy2(item, destination)
    normalize_copied_runtime(runtime)
    bootstrap = runtime / "runtime_bootstrap.py"
    shutil.copy2(BOOTSTRAP, bootstrap)
    bootstrap.chmod(0o644)
    for command in ("playbook", "inventory"):
        launcher = runtime / "bin" / ("ansible-" + command)
        launcher.write_bytes(gateway.canonical_launcher(bootstrap, command))
        launcher.chmod(0o755)
    environment = gateway.runtime_environment(payload / "ansible")
    for command in ("playbook", "inventory"):
        for argument in ("--preflight", "--version"):
            run_bounded([str(runtime / "bin" / ("ansible-" + command)), argument],
                        cwd=payload / "ansible", environment=environment, timeout=30,
                        service_user=service_user,
                        phase=command + "_" + argument.removeprefix("--"))
    check_inventory(gateway, payload, service_user, policy)
    check_playbooks(gateway, payload, service_user)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("release_id")
    parser.add_argument("--source-site", type=Path,
                        default=Path("/usr/lib/python3/dist-packages"))
    parser.add_argument("--managed-profile-catalog", type=Path, default=LAB_CATALOG)
    args = parser.parse_args()
    try:
        prepare(args.release_id, args.source_site,
                catalog_source=args.managed_profile_catalog)
    except (OSError, ValueError, SyntaxError, subprocess.SubprocessError) as exc:
        print("runtime staging rejected: " + str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
