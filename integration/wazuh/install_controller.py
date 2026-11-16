#!/usr/bin/python3 -I
"""Install the Wazuh -> ansible-control gateway on a controller (root, Linux).

Subcommands
  bootstrap  One-time host preparation: service user, directories, SSH key
             material, gateway source and entrypoint, Wazuh agent localfile,
             Ansible Core site-packages.
  release    Verify, extract, seal and activate one release bundle produced by
             build_release.py. Release ids are single-use.

Standard library only. Idempotent; ``--dry-run`` makes no change. Secrets are
never read from, or written into, bundles: an SSH private key is either
supplied with --ssh-key or generated on the controller (--generate-ssh-key);
its private half is never printed.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

sys.dont_write_bytecode = True

BUNDLE_FORMAT = 1
REQUIRED_CORE = "2.21.2"
ENTRYPOINT = Path("/var/ossec/active-response/bin/ansible-job")
OSSEC_CONF = Path("/var/ossec/etc/ossec.conf")
CLIENT_KEYS = Path("/var/ossec/etc/client.keys")
CONFIG_DIR = Path("/etc/ansible-wazuh")
POLICY_PATH = CONFIG_DIR / "jobs.json"
DEPLOYMENT_LOCK = CONFIG_DIR / "deployment.lock"
VAR_DIR = Path("/var/lib/ansible-wazuh")
STATE_DIR = VAR_DIR / "state"
APPROVAL_DIR = VAR_DIR / "approvals"
ACTIVATION_DIR = VAR_DIR / "activated-releases"
RUNTIME_TMP = VAR_DIR / "runtime-tmp"
SSH_DIR = VAR_DIR / "ssh"
SSH_KEY = SSH_DIR / "id_rsa"
KNOWN_HOSTS = SSH_DIR / "known_hosts"
OPT_DIR = Path("/opt/ansible-hardening")
RELEASES_ROOT = OPT_DIR / "releases"
SRC_ROOT = OPT_DIR / "src"
SRC_WAZUH = SRC_ROOT / "integration" / "wazuh"
SITE_PACKAGES = SRC_ROOT / "site-packages"
EVENT_LOG = Path("/var/log/ansible-wazuh-jobs.jsonl")
PYTHON = "/usr/bin/python3"

ID = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}\Z")
HEX64 = re.compile(r"[0-9A-Fa-f]{64}\Z")
NAME_PART = re.compile(r"[A-Za-z0-9._@+=,~-]{1,200}\Z")
# Keep in sync with build_release.GATEWAY_FILES (a unit test asserts it).
GATEWAY_FILES = (
    "managed_job.py", "runtime_bootstrap.py", "prepare_isolated_runtime.py",
    "managed_profiles.py", "managed_supervisor.py", "execution_state.py",
    "launch_claim.py", "retained_observation.py", "execution_observation.py",
    "evidence_reconcile.py",
)
CONTROLLER_TOOLS = ("install_controller.py", "prepare_safety.py")
SOURCE_EXTRAS = ("config",)
ENTRY_SHEBANG = b"#!/usr/bin/python3 -I"

MAX_BUNDLE = 512 * 1024 * 1024
MAX_FILE = 128 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024
MAX_MEMBERS = 100_000
TOP_LEVEL = ("payload", "policy")
POLICY_FILES = ("jobs.json", "profiles.json")
MAX_PAX_HEADERS = 8 * 1024
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
O_BINARY = getattr(os, "O_BINARY", 0)

LOCALFILE_PRESENT = re.compile(r"<location>\s*/var/log/ansible-wazuh-jobs\.jsonl\s*</location>")
COMMAND_PRESENT = re.compile(r"<name>\s*ansible-job\s*</name>")


class InstallError(Exception):
    """Installation must stop; nothing was knowingly left half-activated."""


# =========================================================================== pure helpers

def validate_release_id(value: str) -> str:
    if type(value) is not str or not ID.fullmatch(value) or HEX64.fullmatch(value):
        raise InstallError("invalid release id")
    return value


def parse_sha256_file(text: str, bundle_name: str) -> str:
    """Accept ``<hex>  <name>`` (sha256sum format) or a bare digest."""
    lines = [line for line in text.splitlines() if line.strip()]
    if len(lines) != 1:
        raise InstallError("sha256 file must contain exactly one line")
    fields = lines[0].split()
    if not fields or not re.fullmatch(r"[0-9a-fA-F]{64}", fields[0]) or len(fields) > 2:
        raise InstallError("sha256 file is malformed")
    if len(fields) == 2 and fields[1].lstrip("*") != bundle_name:
        raise InstallError("sha256 file names a different bundle")
    return fields[0].lower()


def read_verified_bundle(bundle: Path, sha256_file: Path | None = None,
                         expect_sha256: str | None = None) -> tuple[bytes, str]:
    """Read the bundle once (hard-bounded) and verify its digest; later steps use these bytes only.

    ``expect_sha256`` is the digest the operator obtained out-of-band and is the only
    trust anchor; the ``.sha256`` file shipped next to the bundle only proves transit
    integrity and is an optional cross-check.
    """
    if bundle.is_symlink() or not bundle.is_file():
        raise InstallError("bundle must be a regular file")
    with open(bundle, "rb") as stream:
        data = stream.read(MAX_BUNDLE + 1)
    if len(data) > MAX_BUNDLE:
        raise InstallError("bundle exceeds the size limit")
    actual = hashlib.sha256(data).hexdigest()
    if sha256_file is not None:
        shipped = parse_sha256_file(sha256_file.read_text(encoding="ascii"), bundle.name)
        if actual != shipped:
            raise InstallError("bundle sha256 mismatch: refusing to install")
    if expect_sha256 is not None:
        if type(expect_sha256) is not str or not HEX64.fullmatch(expect_sha256.strip()):
            raise InstallError("--expect-sha256 must be a 64-character hexadecimal digest")
        if actual != expect_sha256.strip().lower():
            raise InstallError("bundle sha256 differs from --expect-sha256: refusing to install")
    return data, actual


def _allowed_bundle_path(parts: tuple[str, ...]) -> bool:
    """Exactly the layout build_release.py produces (nothing else is ever extracted)."""
    if parts == ("MANIFEST.json",):
        return True
    if parts[0] == "policy":
        return len(parts) == 2 and parts[1] in POLICY_FILES
    if parts[0] != "payload" or len(parts) < 3:
        return False
    if parts[1] == "ansible":
        return parts[2:] == ("ansible.cfg",) or (parts[2] in ("playbooks", "roles") and len(parts) >= 4)
    if parts[1] == "inventory":
        return True
    if parts[1] == "collections":
        return parts[2] == "ansible_collections" and len(parts) >= 4
    return False


def member_parts(name: str) -> tuple[str, ...]:
    """Validate one archive path; return its components."""
    if (not name or "\0" in name or "\\" in name or name.startswith("/") or len(name) > 400):
        raise InstallError(f"unsafe archive path: {name!r}")
    parts = tuple(name.split("/"))
    if len(parts) > 32 or any(part in ("", ".", "..") or not NAME_PART.fullmatch(part)
                              for part in parts):
        raise InstallError(f"unsafe archive path: {name!r}")
    if not _allowed_bundle_path(parts):
        raise InstallError(f"unexpected archive entry: {name!r}")
    return parts


class Inspection:
    def __init__(self, manifest: dict, policy_files: dict[str, bytes], names: list[str]):
        self.manifest = manifest
        self.policy_files = policy_files
        self.names = names


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise InstallError("duplicate JSON key in manifest")
        value[key] = item
    return value


def _manifest_ok(manifest) -> dict:
    if (type(manifest) is not dict or manifest.get("format") != BUNDLE_FORMAT
            or manifest.get("ansible_core") != REQUIRED_CORE
            or type(manifest.get("files")) is not dict or not manifest["files"]
            or type(manifest.get("gateway_files")) is not dict):
        raise InstallError("unsupported or malformed bundle manifest")
    validate_release_id(manifest.get("release_id"))
    for name, digest in manifest["files"].items():
        member_parts(name)
        if type(digest) is not str or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise InstallError("malformed manifest digest")
    return manifest


def inspect_bundle(data: bytes) -> Inspection:
    """Validate every archive member and hash against the manifest; write nothing."""
    manifest = None
    seen: set[str] = set()
    policy_files: dict[str, bytes] = {}
    total = 0
    try:
        archive = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise InstallError("bundle is not a readable tar.gz") from exc
    with archive:
        try:
            for index, member in enumerate(archive):
                if index >= MAX_MEMBERS:
                    raise InstallError("too many archive entries")
                parts = member_parts(member.name)
                if sum(len(str(k)) + len(str(v)) for k, v in member.pax_headers.items()) > MAX_PAX_HEADERS:
                    raise InstallError(f"oversized extended headers: {member.name}")
                if member.isdir():
                    continue
                if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE):
                    raise InstallError(f"links, devices and special entries are refused: {member.name}")
                if member.name in seen or (member.name == "MANIFEST.json" and manifest is not None):
                    raise InstallError(f"duplicate archive entry: {member.name}")
                if member.size > MAX_FILE:
                    raise InstallError(f"archive entry too large: {member.name}")
                total += member.size
                if total > MAX_TOTAL:
                    raise InstallError("bundle expands beyond the size limit")
                digest = hashlib.sha256()
                chunks = []
                stream = archive.extractfile(member)
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
                    if parts[0] in ("MANIFEST.json", "policy"):
                        chunks.append(chunk)
                if parts == ("MANIFEST.json",):
                    if index != 0:
                        raise InstallError("MANIFEST.json must be the first entry")
                    try:
                        manifest = _manifest_ok(json.loads(b"".join(chunks).decode("utf-8"),
                                                           object_pairs_hook=_unique))
                    except (UnicodeError, json.JSONDecodeError) as exc:
                        raise InstallError("manifest is not valid JSON") from exc
                    continue
                if manifest is None:
                    raise InstallError("MANIFEST.json must be the first entry")
                seen.add(member.name)
                if manifest["files"].get(member.name) != digest.hexdigest():
                    raise InstallError(f"entry not in manifest or hash mismatch: {member.name}")
                if parts[0] == "policy":
                    policy_files[member.name] = b"".join(chunks)
        except (tarfile.TarError, OSError, EOFError) as exc:
            raise InstallError("bundle is corrupt") from exc
    if manifest is None:
        raise InstallError("bundle has no manifest")
    if seen != set(manifest["files"]):
        raise InstallError("bundle and manifest list different files")
    for required in ("policy/jobs.json", "policy/profiles.json", "payload/inventory/hosts.yml",
                     "payload/ansible/ansible.cfg"):
        if required not in seen:
            raise InstallError(f"bundle lacks {required}")
    return Inspection(manifest, policy_files, sorted(seen))


def _write_new_file(path: Path, data_chunks, mode: int, uid: int | None, gid: int | None) -> str:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW | O_BINARY, mode)
    digest = hashlib.sha256()
    try:
        for chunk in data_chunks:
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                view = view[os.write(fd, view):]
        if hasattr(os, "fchmod"):
            os.fchmod(fd, mode)
        if uid is not None and hasattr(os, "fchown"):
            os.fchown(fd, uid, gid if gid is not None else -1)
        os.fsync(fd)
    finally:
        os.close(fd)
    return digest.hexdigest()


def extract_payload(data: bytes, destination: Path, manifest: dict, *,
                    uid: int | None = None, gid: int | None = None) -> int:
    """Extract only ``payload/`` into a destination that does not exist yet.

    Files are created exclusively (never through a link), with fixed modes
    (0644 files, 0755 directories) and re-hashed while written.
    """
    if destination.exists() or destination.is_symlink():
        raise InstallError(f"destination already exists: {destination}")
    os.mkdir(destination, 0o755)
    count = 0
    created = {destination}

    def make_dir(path: Path) -> None:
        if path in created:
            return
        make_dir(path.parent)
        os.mkdir(path, 0o755)
        if hasattr(os, "chmod"):
            os.chmod(path, 0o755)
        if uid is not None and hasattr(os, "chown"):
            os.chown(path, uid, gid if gid is not None else -1)
        created.add(path)

    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for member in archive:
            parts = member_parts(member.name)
            if parts[0] != "payload" or member.isdir():
                continue
            if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE):
                raise InstallError(f"links and special entries are refused: {member.name}")
            relative = Path(*parts[1:])
            target = destination / relative
            make_dir(target.parent)
            stream = archive.extractfile(member)
            digest = _write_new_file(target, iter(lambda: stream.read(1024 * 1024), b""),
                                     0o644, uid, gid)
            if digest != manifest["files"].get(member.name):
                raise InstallError(f"hash mismatch while extracting {member.name}")
            count += 1
    if uid is not None and hasattr(os, "chown"):
        os.chown(destination, uid, gid if gid is not None else -1)
    return count


def check_gateway_files(manifest: dict, directory: Path) -> None:
    """The installed gateway sources must be byte-identical to the build tree."""
    for name, expected in manifest["gateway_files"].items():
        if name not in GATEWAY_FILES:
            raise InstallError(f"manifest names an unknown gateway file: {name}")
        path = directory / name
        try:
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            raise InstallError(f"installed gateway file unreadable: {path}") from exc
        if actual != expected:
            raise InstallError(f"{name} differs from the version the bundle was built with; "
                               "refresh the controller source (bootstrap) before this release")
    if set(manifest["gateway_files"]) != set(GATEWAY_FILES):
        raise InstallError("manifest gateway file set is unexpected")


def render_policy(jobs_raw: bytes, release_id: str) -> dict:
    """Derive the gateway policy from the sealed jobs subset (paths are fixed here)."""
    try:
        jobs = json.loads(jobs_raw.decode("utf-8"), object_pairs_hook=_unique)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise InstallError("policy/jobs.json is not valid JSON") from exc
    if type(jobs) is not dict or set(jobs) != {"version", "service_user", "targets", "controls"}:
        raise InstallError("policy/jobs.json has an unexpected shape")
    payload = RELEASES_ROOT / validate_release_id(release_id) / "payload"
    return {"version": 2, "release_id": release_id,
            "ansible_root": str(payload / "ansible"),
            "ansible_bin_dir": str(payload / "runtime" / "bin"),
            "inventory": str(payload / "inventory" / "hosts.yml"),
            "service_user": jobs["service_user"],
            "targets": jobs["targets"], "controls": jobs["controls"]}


_COMMENT = re.compile(r"<!--.*?-->", re.S)


def merge_ossec_block(conf: str, snippet: str, present: re.Pattern) -> tuple[str, bool]:
    """Insert ``snippet`` inside the last <ossec_config> block unless already present."""
    masked = _COMMENT.sub(lambda match: " " * len(match.group()), conf)
    if present.search(masked):
        return conf, False
    body = "\n".join(("  " + line.rstrip()) if line.strip() else ""
                     for line in snippet.strip("\n").splitlines())
    close = masked.rfind("</ossec_config>")
    if close == -1:
        return conf.rstrip("\n") + "\n\n<ossec_config>\n" + body + "\n</ossec_config>\n", True
    head = conf[:close].rstrip(" \t")
    if not head.endswith("\n"):
        head += "\n"
    return head + "\n" + body + "\n" + conf[close:], True


def validate_ossec_xml(conf: str) -> None:
    """Wazuh files may hold several root blocks; wrap them to check well-formedness."""
    body = re.sub(r"^\s*<\?xml[^>]*\?>", "", conf)
    try:
        ET.fromstring("<wazuh_root>" + body + "</wazuh_root>")
    except ET.ParseError as exc:
        raise InstallError(f"ossec.conf is not well-formed XML: {exc}") from exc


def source_version(release_py: str) -> str | None:
    match = re.search(r'(?m)^__version__\s*=\s*[\'"]([^\'"]+)[\'"]', release_py)
    return match.group(1) if match else None


# =========================================================================== context

class Ctx:
    def __init__(self, dry_run: bool):
        self.dry_run = dry_run
        self.warnings: list[str] = []

    def say(self, message: str) -> None:
        print(("[dry-run] " if self.dry_run else "") + message, flush=True)

    def warn(self, message: str) -> None:
        self.warnings.append(message)
        print("WARNING: " + message, file=sys.stderr, flush=True)

    def run(self, argv: list[str], *, check: bool = True, **kwargs) -> subprocess.CompletedProcess:
        self.say("run: " + " ".join(argv))
        if self.dry_run:
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        result = subprocess.run(argv, check=False, **kwargs)
        if check and result.returncode != 0:
            raise InstallError(f"command failed ({result.returncode}): {argv[0]}")
        return result


def require_root_linux(ctx: Ctx) -> None:
    if sys.platform != "linux":
        raise InstallError("a Linux controller is required")
    if os.geteuid() != 0 and not ctx.dry_run:
        raise InstallError("run as root")
    os.umask(0o022)


def probe(path: Path) -> bool:
    """Existence check that tolerates an unprivileged dry run."""
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False
    except PermissionError:
        return False


def ensure_dir(ctx: Ctx, path: Path, mode: int, uid: int | None = 0, gid: int | None = 0) -> None:
    try:
        info = path.lstat()
    except (FileNotFoundError, PermissionError):
        info = None
    if info is None:
        ctx.say(f"create directory {path} ({mode:04o})")
        if ctx.dry_run:
            return
        os.mkdir(path, mode)
    elif not stat.S_ISDIR(info.st_mode):
        raise InstallError(f"{path} exists and is not a directory")
    if ctx.dry_run:
        return
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise InstallError(f"{path} is not a directory")
    fix_mode = stat.S_IMODE(info.st_mode) != mode
    fix_owner = uid is not None and (info.st_uid, info.st_gid) != (uid, gid)
    if fix_mode:
        ctx.say(f"fix mode of {path} to {mode:04o}")
    if fix_owner:
        ctx.say(f"fix owner of {path}")
    if fix_mode or fix_owner:
        _fix_directory(path, info, mode if fix_mode else None, (uid, gid) if fix_owner else None)


def _fix_directory(path: Path, expected: os.stat_result, mode: int | None,
                   owner: tuple[int, int] | None) -> None:
    """chmod/chown a directory through an O_NOFOLLOW descriptor, never through a link."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != (expected.st_dev, expected.st_ino)):
            raise InstallError(f"{path} changed while it was being prepared")
        if mode is not None:
            os.fchmod(fd, mode)
        if owner is not None:
            os.fchown(fd, owner[0], owner[1])
    finally:
        os.close(fd)


def ensure_tree(ctx: Ctx, base: Path, path: Path) -> None:
    """Create root-owned 0755 directories from ``base`` down to ``path``."""
    current = base
    ensure_dir(ctx, current, 0o755)
    for part in path.relative_to(base).parts:
        current = current / part
        ensure_dir(ctx, current, 0o755)


def atomic_write(path: Path, data: bytes, mode: int, uid: int, gid: int) -> None:
    temporary = path.with_name("." + path.name + f".tmp{os.getpid()}")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fchown(stream.fileno(), uid, gid)
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    dir_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def sha_of(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except FileNotFoundError:
        return None


# =========================================================================== bootstrap

def ensure_service_user(ctx: Ctx, name: str) -> tuple[int | None, int | None]:
    import pwd
    if not ID.fullmatch(name) or name == "root":
        raise InstallError("invalid service user name")
    try:
        account = pwd.getpwnam(name)
    except KeyError:
        ctx.run(["useradd", "--system", "--no-create-home", "--home-dir", "/nonexistent",
                 "--shell", "/usr/sbin/nologin", name])
        if ctx.dry_run:
            return None, None
        account = pwd.getpwnam(name)
    if account.pw_uid == 0:
        raise InstallError("the service account must not be root")
    if account.pw_shell not in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false"):
        ctx.warn(f"service user {name} has a login shell ({account.pw_shell})")
    ctx.say(f"service user {name} uid={account.pw_uid}")
    return account.pw_uid, account.pw_gid


def ensure_directories(ctx: Ctx, uid: int | None, gid: int | None) -> None:
    ensure_dir(ctx, CONFIG_DIR, 0o700)
    if probe(DEPLOYMENT_LOCK):
        info = DEPLOYMENT_LOCK.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size != 0:
            raise InstallError("deployment.lock exists but is not an empty regular file")
        if not ctx.dry_run and stat.S_IMODE(info.st_mode) != 0o600:
            os.chmod(DEPLOYMENT_LOCK, 0o600)
    else:
        ctx.say(f"create empty {DEPLOYMENT_LOCK} (0600)")
        if not ctx.dry_run:
            os.close(os.open(DEPLOYMENT_LOCK, os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW, 0o600))
    ensure_dir(ctx, VAR_DIR, 0o755)
    for path in (STATE_DIR, APPROVAL_DIR, ACTIVATION_DIR):
        ensure_dir(ctx, path, 0o700)
    for path in (RUNTIME_TMP, SSH_DIR):
        ensure_dir(ctx, path, 0o700, uid, gid)
    ensure_dir(ctx, OPT_DIR, 0o755)
    ensure_dir(ctx, RELEASES_ROOT, 0o755)
    ensure_tree(ctx, OPT_DIR, SRC_WAZUH)
    if probe(EVENT_LOG):
        info = EVENT_LOG.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise InstallError("event log must be a regular file")
        if not ctx.dry_run and stat.S_IMODE(info.st_mode) != 0o600:
            os.chmod(EVENT_LOG, 0o600)
    else:
        ctx.say(f"create {EVENT_LOG} (0600)")
        if not ctx.dry_run:
            os.close(os.open(EVENT_LOG, os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW, 0o600))


def generate_ssh_keypair(ctx: Ctx, uid: int | None, gid: int | None) -> None:
    """Generate the key pair in a root-only scratch directory, then install it.

    SSH_DIR belongs to the service user, so root never runs ssh-keygen, chmod or
    chown inside it. Both files are created exclusively and without following
    links; owner and mode are applied through the opened descriptor.
    """
    public_target = Path(str(SSH_KEY) + ".pub")
    if probe(SSH_KEY) or probe(public_target):
        raise InstallError(f"{SSH_KEY} or {public_target} already exists; refusing to overwrite")
    ctx.say(f"generate an ed25519 key in a root-only temporary directory and install it to {SSH_KEY}")
    if ctx.dry_run:
        return
    scratch = Path(tempfile.mkdtemp(prefix="ansible-wazuh-keygen-"))
    try:
        os.chmod(scratch, 0o700)
        ctx.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "ansible-wazuh-controller",
                 "-f", str(scratch / "key")])
        private = (scratch / "key").read_bytes()
        public = (scratch / "key.pub").read_bytes()
        _write_new_file(SSH_KEY, [private], 0o600, uid, gid)
        try:
            _write_new_file(public_target, [public], 0o644, uid, gid)
        except BaseException:
            SSH_KEY.unlink(missing_ok=True)
            raise
        print("Authorize this PUBLIC key for the automation account on every managed node:")
        print(public.decode("ascii").strip())
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def ensure_ssh_material(ctx: Ctx, args, uid: int | None, gid: int | None) -> None:
    """Install or generate the controller's SSH key; known_hosts is public data."""
    if args.ssh_key and args.generate_ssh_key:
        raise InstallError("--ssh-key and --generate-ssh-key are mutually exclusive")
    if args.ssh_key:
        source = Path(args.ssh_key)
        if source.is_symlink() or not source.is_file() or source.stat().st_size > 16384:
            raise InstallError("--ssh-key must be a regular private key file (<= 16 KiB)")
        material = source.read_bytes()
        if not re.search(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", material):
            raise InstallError("--ssh-key does not look like a PEM/OpenSSH private key")
        if probe(SSH_KEY):
            if sha_of(SSH_KEY) != hashlib.sha256(material).hexdigest():
                raise InstallError(f"{SSH_KEY} already exists with different content; refusing to replace")
            ctx.say("SSH key already installed")
        else:
            ctx.say(f"install SSH private key to {SSH_KEY} (0600, service user); content is not displayed")
            if not ctx.dry_run:
                check = subprocess.run(["ssh-keygen", "-y", "-P", "", "-f", str(source)],
                                       capture_output=True, text=True, check=False)
                if check.returncode != 0:
                    raise InstallError("ssh-keygen cannot read the key (passphrase-protected or invalid)")
                _write_new_file(SSH_KEY, [material], 0o600, uid, gid)
                ctx.say("public key: " + check.stdout.strip())
    elif args.generate_ssh_key:
        if probe(SSH_KEY):
            ctx.say("SSH key already present; not generating a new one")
        else:
            generate_ssh_keypair(ctx, uid, gid)
    elif not probe(SSH_KEY):
        ctx.warn(f"no SSH key at {SSH_KEY}: rerun with --ssh-key PATH or --generate-ssh-key "
                 "before the first CHECK")
    if args.known_hosts:
        hosts = Path(args.known_hosts)
        text = hosts.read_text(encoding="utf-8")
        for line in text.splitlines():
            if line.strip() and not line.startswith("#") and (
                    len(line.split()) < 3 or "PRIVATE KEY" in line):
                raise InstallError("--known-hosts must contain only public host key lines")
        if probe(KNOWN_HOSTS) and sha_of(KNOWN_HOSTS) == hashlib.sha256(text.encode()).hexdigest():
            ctx.say("known_hosts already up to date")
        else:
            ctx.say(f"write {KNOWN_HOSTS} (0600, service user)")
            if not ctx.dry_run:
                atomic_write(KNOWN_HOSTS, text.encode("utf-8"), 0o600, uid, gid)
    elif not probe(KNOWN_HOSTS):
        ctx.say(f"create empty {KNOWN_HOSTS} (0600); add host keys with --known-hosts or ssh-keyscan")
        if not ctx.dry_run:
            _write_new_file(KNOWN_HOSTS, [], 0o600, uid, gid)


def install_source(ctx: Ctx, force_gateway: bool) -> None:
    """Copy the reviewed gateway source, controller tools and config templates."""
    here = Path(__file__).resolve().parent
    for name in GATEWAY_FILES + CONTROLLER_TOOLS:
        source = here / name
        if not source.is_file() or source.is_symlink():
            raise InstallError(f"source file missing next to the installer: {name}")
        if b"\r" in source.read_bytes():
            raise InstallError(f"{name} contains CR characters; use LF line endings")
    gateway = (here / "managed_job.py").read_bytes()
    if gateway.split(b"\n", 1)[0] != ENTRY_SHEBANG:
        raise InstallError("managed_job.py must start with " + ENTRY_SHEBANG.decode())
    installed = sha_of(ENTRYPOINT)
    wanted = hashlib.sha256(gateway).hexdigest()
    if installed not in (None, wanted) and not force_gateway:
        raise InstallError("a different gateway entrypoint is installed; changing it invalidates "
                           "existing check evidence. Use --force-update-gateway to replace it")
    for name in GATEWAY_FILES + CONTROLLER_TOOLS:
        _install_file(ctx, here / name, SRC_WAZUH / name, 0o644, 0, 0)
    for extra in SOURCE_EXTRAS:
        directory = here / extra
        if directory.is_dir():
            ensure_dir(ctx, SRC_WAZUH / extra, 0o755)
            for item in sorted(directory.iterdir()):
                if item.is_file() and not item.is_symlink():
                    _install_file(ctx, item, SRC_WAZUH / extra / item.name, 0o644, 0, 0)
    import grp
    try:
        group = grp.getgrnam("wazuh").gr_gid
    except KeyError as exc:
        if ctx.dry_run:
            group = 0
        else:
            raise InstallError("group 'wazuh' not found: install the Wazuh agent first") from exc
    if not probe(ENTRYPOINT.parent):
        if not ctx.dry_run:
            raise InstallError(f"{ENTRYPOINT.parent} not found: install the Wazuh agent first")
    _install_file(ctx, here / "managed_job.py", ENTRYPOINT, 0o750, 0, group)


def _install_file(ctx: Ctx, source: Path, target: Path, mode: int, uid: int, gid: int) -> None:
    data = source.read_bytes()
    try:
        current = target.lstat()
        same = (stat.S_ISREG(current.st_mode) and target.read_bytes() == data
                and stat.S_IMODE(current.st_mode) == mode and (current.st_uid, current.st_gid) == (uid, gid))
    except (FileNotFoundError, PermissionError):
        same = False
    if same:
        return
    ctx.say(f"install {target} ({mode:04o})")
    if not ctx.dry_run:
        atomic_write(target, data, mode, uid, gid)


def configure_agent(ctx: Ctx, restart: bool) -> bool:
    snippet_path = Path(__file__).resolve().parent / "config" / "ansible_job_localfile.xml"
    snippet = snippet_path.read_text(encoding="utf-8")
    if not probe(OSSEC_CONF):
        if ctx.dry_run:
            ctx.say(f"would add the Ansible job localfile to {OSSEC_CONF}")
            return False
        raise InstallError(f"{OSSEC_CONF} not found: install the Wazuh agent first")
    original = OSSEC_CONF.read_text(encoding="utf-8")
    validate_ossec_xml(original)
    merged, changed = merge_ossec_block(original, snippet, LOCALFILE_PRESENT)
    if not changed:
        ctx.say("agent localfile already configured")
        return False
    validate_ossec_xml(merged)
    info = OSSEC_CONF.stat()
    ctx.say(f"add localfile for {EVENT_LOG} to {OSSEC_CONF} (backup kept alongside)")
    if not ctx.dry_run:
        backup = OSSEC_CONF.with_name(OSSEC_CONF.name + ".bak-ansible-job")
        if not probe(backup):
            atomic_write(backup, original.encode("utf-8"), stat.S_IMODE(info.st_mode),
                         info.st_uid, info.st_gid)
        atomic_write(OSSEC_CONF, merged.encode("utf-8"), stat.S_IMODE(info.st_mode),
                     info.st_uid, info.st_gid)
        if restart:
            ctx.run(["systemctl", "restart", "wazuh-agent"])
    return True


def ensure_site_packages(ctx: Ctx, wheelhouse: str | None, online: bool) -> bool:
    release_py = SITE_PACKAGES / "ansible" / "release.py"
    if probe(release_py):
        version = source_version(release_py.read_text(encoding="utf-8"))
        if version != REQUIRED_CORE:
            raise InstallError(f"{SITE_PACKAGES} holds Ansible Core {version}; {REQUIRED_CORE} required")
        ctx.say(f"site-packages already holds Ansible Core {version}")
        return True
    if not wheelhouse and not online:
        ctx.warn(f"{SITE_PACKAGES} is not populated: rerun bootstrap with --wheelhouse DIR "
                 "(offline, recommended) or --online; `release` will refuse until then")
        return False
    staging = SRC_ROOT / f".site-packages-{os.getpid()}"
    command = [PYTHON, "-m", "pip", "install", "--target", str(staging), "--no-compile",
               "--only-binary=:all:", "--disable-pip-version-check", "--root-user-action=ignore"]
    command += ["--no-index", "--find-links", wheelhouse] if wheelhouse else []
    command.append(f"ansible-core=={REQUIRED_CORE}")
    ctx.run(command)
    if ctx.dry_run:
        return False
    try:
        shutil.rmtree(staging / "bin", ignore_errors=True)
        for current, directories, files in os.walk(staging, followlinks=False):
            for name in directories + files:
                item = Path(current) / name
                info = item.lstat()
                if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                    raise InstallError(f"unexpected entry in installed packages: {item}")
                os.chown(item, 0, 0, follow_symlinks=False)
                os.chmod(item, 0o755 if stat.S_ISDIR(info.st_mode) else 0o644)
        os.chown(staging, 0, 0, follow_symlinks=False)
        os.chmod(staging, 0o755)
        version = source_version((staging / "ansible" / "release.py").read_text(encoding="utf-8"))
        if version != REQUIRED_CORE:
            raise InstallError(f"installed Ansible Core {version}, {REQUIRED_CORE} required")
        os.rename(staging, SITE_PACKAGES)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return True


def cmd_bootstrap(args) -> int:
    ctx = Ctx(args.dry_run)
    require_root_linux(ctx)
    ctx.say("step 1/5: service user")
    uid, gid = ensure_service_user(ctx, args.service_user)
    ctx.say("step 2/5: directories, deployment lock, event log")
    ensure_directories(ctx, uid, gid)
    ensure_ssh_material(ctx, args, uid, gid)
    ctx.say("step 3/5: gateway source and entrypoint")
    install_source(ctx, args.force_update_gateway)
    ctx.say("step 4/5: Wazuh agent localfile")
    if probe(CLIENT_KEYS) and CLIENT_KEYS.stat().st_size == 0:
        ctx.warn("the Wazuh agent has no client.keys: enroll it before ordering jobs")
    configure_agent(ctx, restart=not args.no_restart_agent)
    ctx.say("step 5/5: isolated Ansible runtime packages")
    ready = ensure_site_packages(ctx, args.wheelhouse, args.online)
    print("bootstrap complete" + ("" if ready else " (site-packages pending)"))
    print("next: install_controller.py release --bundle <ID>.tar.gz --expect-sha256 <HEX from the build "
          "output or change ticket> --expect-release-id <ID> [--sha256 <ID>.tar.gz.sha256]")
    return 0


# =========================================================================== release

def load_gateway():
    """Import the installed gateway source (identical to the entrypoint) for sealing."""
    source = SRC_WAZUH / "managed_job.py"
    if sha_of(source) != sha_of(ENTRYPOINT):
        raise InstallError("controller source and installed entrypoint differ; run bootstrap")
    spec = importlib.util.spec_from_file_location("managed_job_installer", source)
    if spec is None or spec.loader is None:
        raise InstallError("gateway source cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def assert_no_links(root: Path) -> None:
    """The gateway rejects links and multi-link files anywhere in the payload."""
    for current, directories, files in os.walk(root, followlinks=False):
        for name in directories + files:
            info = (Path(current) / name).lstat()
            if stat.S_ISLNK(info.st_mode) or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1):
                raise InstallError(f"payload holds a link or multi-link file: {Path(current) / name}")
            if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise InstallError(f"payload holds a special file: {Path(current) / name}")


def used_release_ids(ctx: Ctx, release_id: str) -> None:
    if probe(RELEASES_ROOT / release_id):
        raise InstallError(f"release {release_id} already exists under {RELEASES_ROOT}")
    if probe(ACTIVATION_DIR / release_id):
        raise InstallError(f"release id {release_id} was activated before; release ids are single-use")
    if probe(POLICY_PATH):
        try:
            active = json.loads(POLICY_PATH.read_text(encoding="utf-8")).get("release_id")
        except (OSError, ValueError):
            raise InstallError("the active policy is unreadable; refusing to continue") from None
        if active == release_id:
            raise InstallError(f"release {release_id} is the active release")


def cmd_release(args) -> int:
    ctx = Ctx(args.dry_run)
    require_root_linux(ctx)
    if not args.expect_sha256 or not args.expect_release_id:
        raise InstallError("--expect-sha256 and --expect-release-id are required")
    data, digest = read_verified_bundle(Path(args.bundle),
                                        Path(args.sha256) if args.sha256 else None,
                                        args.expect_sha256)
    ctx.say(f"bundle sha256 verified against the out-of-band digest: {digest}")
    inspection = inspect_bundle(data)
    manifest = inspection.manifest
    release_id = manifest["release_id"]
    if args.expect_release_id != release_id:
        raise InstallError("bundle release id differs from --expect-release-id")
    ctx.say(f"bundle valid: release {release_id}, {len(inspection.names)} files, "
            f"commit {manifest.get('source_commit')}")
    if manifest.get("source_dirty"):
        ctx.warn("the bundle was built from a tree with uncommitted changes")
    if not manifest.get("has_collections"):
        ctx.warn("the bundle carries no Ansible collections; the release will likely fail validation")
    if not probe(SRC_WAZUH / "managed_job.py") or not probe(ENTRYPOINT):
        raise InstallError("controller is not bootstrapped (gateway source or entrypoint missing)")
    check_gateway_files(manifest, SRC_WAZUH)
    if sha_of(ENTRYPOINT) != manifest["gateway_files"]["managed_job.py"]:
        raise InstallError("installed entrypoint differs from the bundle's gateway version")
    ready = probe(SITE_PACKAGES / "ansible" / "release.py")
    if not ready:
        raise InstallError(f"{SITE_PACKAGES} is not populated; run bootstrap with --wheelhouse/--online")
    for directory in (CONFIG_DIR, ACTIVATION_DIR, STATE_DIR, RUNTIME_TMP):
        if not probe(directory) and not ctx.dry_run:
            raise InstallError(f"{directory} missing: run bootstrap first")
    used_release_ids(ctx, release_id)
    policy = render_policy(inspection.policy_files["policy/jobs.json"], release_id)
    import pwd
    try:
        pwd.getpwnam(policy["service_user"])
    except KeyError as exc:
        if not ctx.dry_run:
            raise InstallError(f"service user {policy['service_user']} does not exist") from exc
    release = RELEASES_ROOT / release_id
    payload = release / "payload"
    ctx.say(f"extract payload to {payload}")
    ctx.say("write policy.json (0600) and profiles catalog; create home/plugins/collections")
    ctx.say("stage the isolated runtime with prepare_isolated_runtime.py "
            "(runs ansible --syntax-check for every job; can take several minutes)")
    ctx.say("seal release.json from the payload tree digest")
    ctx.say("activate" if not args.no_activate else "skip activation (--no-activate)")
    if args.dry_run:
        print("dry run complete: no change made")
        return 0

    created = False
    try:
        os.mkdir(release, 0o755)
        created = True
        count = extract_payload(data, payload, manifest, uid=0, gid=0)
        for name in ("home", "plugins", "collections"):
            if not probe(payload / name):
                os.mkdir(payload / name, 0o755)
        assert_no_links(payload)
        policy_raw = (json.dumps(policy, sort_keys=True, indent=2) + "\n").encode("utf-8")
        _write_new_file(release / "policy.json", [policy_raw], 0o600, 0, 0)
        _write_new_file(release / "profiles.catalog.json",
                        [inspection.policy_files["policy/profiles.json"]], 0o644, 0, 0)
        ctx.say(f"extracted {count} files; staging runtime")
        result = subprocess.run(
            [PYTHON, "-I", str(SRC_WAZUH / "prepare_isolated_runtime.py"), release_id,
             "--source-site", str(SITE_PACKAGES),
             "--managed-profile-catalog", str(release / "profiles.catalog.json")],
            check=False, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"})
        if result.returncode != 0:
            raise InstallError("runtime staging rejected the release (see the message above)")
        assert_no_links(payload)
        gateway = load_gateway()
        tree = gateway.trusted_tree_digest(payload)
        descriptor = {"version": 1, "release_id": release_id,
                      "policy_sha256": hashlib.sha256(policy_raw).hexdigest(),
                      "payload_sha256": tree.hex()}
        _write_new_file(release / "release.json",
                        [(json.dumps(descriptor, sort_keys=True, indent=2) + "\n").encode("utf-8")],
                        0o600, 0, 0)
        gateway.policy_and_hash(release / "policy.json")
        ctx.say("release sealed and verified: payload_sha256=" + descriptor["payload_sha256"])
        if args.no_activate:
            print(f"release {release_id} staged and sealed, not activated. Activate with:")
            print(f"  {ENTRYPOINT} --activate {release_id}")
            return 0
        outcome = subprocess.run([str(ENTRYPOINT), "--activate", release_id], check=False)
        if outcome.returncode != 0:
            raise InstallError(f"activation rejected (exit {outcome.returncode})")
        print(f"release {release_id} ACTIVE (payload_sha256={descriptor['payload_sha256']})")
        print("next: run a CHECK from Wazuh, review the diff, then the safety/approval procedure")
        return 0
    except BaseException:
        if created and not args.keep_on_failure and not probe(ACTIVATION_DIR / release_id):
            shutil.rmtree(release, ignore_errors=True)
            print(f"removed incomplete release directory {release}", file=sys.stderr)
        elif created:
            print(f"left {release} in place for inspection", file=sys.stderr)
        raise


# =========================================================================== CLI

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    boot = sub.add_parser("bootstrap", help="prepare the controller (idempotent)")
    boot.add_argument("--dry-run", action="store_true", help="show actions, change nothing")
    boot.add_argument("--service-user", default="ansible-wazuh")
    group = boot.add_mutually_exclusive_group()
    group.add_argument("--ssh-key", metavar="PATH", help="install this private key for managed nodes")
    group.add_argument("--generate-ssh-key", action="store_true",
                       help="generate an ed25519 key on the controller and print the public half")
    boot.add_argument("--known-hosts", metavar="FILE", help="public host keys for managed nodes")
    pkg = boot.add_mutually_exclusive_group()
    pkg.add_argument("--wheelhouse", metavar="DIR", help="offline wheels for ansible-core 2.21.2")
    pkg.add_argument("--online", action="store_true", help="install ansible-core from the pip index")
    boot.add_argument("--no-restart-agent", action="store_true")
    boot.add_argument("--force-update-gateway", action="store_true",
                      help="replace an installed, different gateway entrypoint")
    boot.set_defaults(handler=cmd_bootstrap)
    rel = sub.add_parser("release", help="verify, install, seal and activate a bundle")
    rel.add_argument("--bundle", required=True, metavar="X.tar.gz")
    rel.add_argument("--expect-sha256", required=True, metavar="HEX",
                     help="SHA-256 of the bundle obtained out-of-band (build output or change "
                          "ticket); the only trust anchor")
    rel.add_argument("--expect-release-id", required=True, metavar="ID",
                     help="release id the operator expects the bundle to contain")
    rel.add_argument("--sha256", metavar="X.tar.gz.sha256",
                     help="optional: the .sha256 file shipped with the bundle, used as a transit "
                          "cross-check only (it does not authenticate the bundle)")
    rel.add_argument("--no-activate", action="store_true", help="stage and seal only")
    rel.add_argument("--keep-on-failure", action="store_true")
    rel.add_argument("--dry-run", action="store_true", help="verify the bundle, change nothing")
    rel.set_defaults(handler=cmd_release)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.handler(args)
    except InstallError as exc:
        print("installation refused: " + str(exc), file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"installation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
