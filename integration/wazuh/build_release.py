#!/usr/bin/env python3
"""Build a deterministic release bundle for the Wazuh -> ansible-control gateway.

Runs on an administrator workstation (standard library only). It combines the
project tree (playbooks and roles, taken from Git) with the institution's *site
directory* (inventory, variables and policy, versioned in the institution's
private Git) into one ``<release-id>.tar.gz`` plus a ``.sha256`` file.

The bundle is copied to the controller and installed with
``install_controller.py release``. Wazuh never sends inventory or variables;
whatever is in this bundle is the only source of truth for a release.

Fail-closed rules: symbolic links, special files, private keys, plaintext
credentials, vault-encrypted content and unexpected site entries are refused.
Secrets (SSH private keys, Wazuh API passwords) never belong in a bundle.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
from pathlib import Path


BUNDLE_FORMAT = 1
REQUIRED_CORE = "2.21.2"
PLACEHOLDER = "@RELEASE_ID@"
SSH_KEY_PATH = "/var/lib/ansible-wazuh/ssh/id_rsa"
KNOWN_HOSTS_PATH = "/var/lib/ansible-wazuh/ssh/known_hosts"
MAX_SITE_FILE = 1024 * 1024
FIXED_MTIME = 0

# Same grammar as the gateway (managed_job.ID and managed_identifier).
ID = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}\Z")
HEX64 = re.compile(r"[0-9A-Fa-f]{64}\Z")
NAME_PART = re.compile(r"[A-Za-z0-9._@+=,~-]{1,200}\Z")
PLATFORMS = ("ubuntu24", "debian12")
# Mirrors managed_job.REMEDIATION_CONTROLS (identical for both platforms).
CONTROLS = {"cron_hourly": "cis_2_4_1_3", "cron_daily": "cis_2_4_1_4"}
# Files that make up the gateway on the controller. Their hashes are recorded
# in the manifest so the installer can prove the controller runs the same code.
GATEWAY_FILES = (
    "managed_job.py", "runtime_bootstrap.py", "prepare_isolated_runtime.py",
    "managed_profiles.py", "managed_supervisor.py", "execution_state.py",
    "launch_claim.py", "retained_observation.py", "execution_observation.py",
    "evidence_reconcile.py",
)

SITE_ROOT_IGNORED = (".git", ".gitignore", ".gitattributes", ".gitkeep")
SITE_EXTENSIONS = (".yml", ".yaml", ".json", ".ini", ".txt", ".j2")
SECRETISH_SAFE = {"", "true", "false", "yes", "no", "null", "~", "none", "[]", "{}", "omit"}

PEM_PRIVATE = re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|PuTTY-User-Key-File-\d")
VAULT = re.compile(r"\$ANSIBLE_VAULT;|!vault\b")
CREDENTIAL_KEY = re.compile(
    r"\bansible_(?:ssh_|become_|sudo_|su_|connection_)?pass(?:word)?[\"']?\s*[:=]")
# The optional quote after the key name catches JSON/quoted-YAML spellings.
KEY_FILE = re.compile(r"\bansible_(?:ssh_)?private_key_file[\"']?\s*[:=]\s*(\S+)")
SECRETISH = re.compile(
    r"^\s*[\"']?([\w.-]*(?:password|passwd|passphrase|secret|token|api_?key|private_key)"
    r"[\w.-]*)[\"']?\s*[:=]\s*(.*?)\s*,?\s*$", re.IGNORECASE)
INSECURE_SSH = re.compile(
    r"StrictHostKeyChecking\s*[= ]\s*no\b|UserKnownHostsFile\s*=\s*/dev/null", re.IGNORECASE)


class BuildError(Exception):
    """The bundle must not be produced."""


def validate_release_id(value: str) -> str:
    if type(value) is not str or not ID.fullmatch(value) or HEX64.fullmatch(value):
        raise BuildError("release id must match [A-Za-z][A-Za-z0-9_.-]{0,63} and not be a digest")
    return value


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BuildError("duplicate JSON key: " + key)
        result[key] = value
    return result


def load_json(raw: bytes, name: str):
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise BuildError(f"{name} is not valid JSON: {exc}") from exc


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------- scanning

def scan_project_bytes(name: str, data: bytes) -> list[str]:
    """Project files only need the private-key guard."""
    if PEM_PRIVATE.search(data):
        return [f"{name}: private key material"]
    return []


def scan_site_text(name: str, data: bytes, *, allow_lab_ssh: bool = False,
                   allowed_keys: frozenset[str] = frozenset()) -> list[str]:
    """Return refusal reasons for one site file (empty list means clean)."""
    problems = scan_project_bytes(name, data)
    if b"\0" in data:
        return problems + [f"{name}: binary content"]
    try:
        text = data.decode("utf-8")
    except UnicodeError:
        return problems + [f"{name}: not UTF-8 text"]
    if VAULT.search(text):
        problems.append(f"{name}: vault-encrypted content (the gateway has no vault password)")
    if not allow_lab_ssh and INSECURE_SSH.search(text):
        problems.append(f"{name}: insecure SSH host key options (use {KNOWN_HOSTS_PATH}"
                        " with StrictHostKeyChecking=yes)")
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if CREDENTIAL_KEY.search(line):
            problems.append(f"{name}:{number}: connection or become password variable")
        found = KEY_FILE.search(line)
        if found and found.group(1).strip("\"',}]") != SSH_KEY_PATH:
            problems.append(f"{name}:{number}: ansible_ssh_private_key_file must be {SSH_KEY_PATH}")
        match = SECRETISH.match(line)
        if match and match.group(1) not in allowed_keys:
            key, value = match.group(1).lower(), match.group(2)
            value = re.split(r"\s#", value, maxsplit=1)[0].strip().strip("\"'")
            if key.endswith(("_file", "_path")) or "private_key_file" in key:
                continue
            if (value.lower() in SECRETISH_SAFE or value.startswith("{{")
                    or re.fullmatch(r"\d+", value)):
                continue
            problems.append(f"{name}:{number}: literal value for secret-like key '{match.group(1)}'"
                            " (use --allow-key after review if this is not a secret)")
    return problems


# --------------------------------------------------------------------------- tree walking

def check_name(name: str, where: str) -> None:
    if name in (".", "..") or not NAME_PART.fullmatch(name):
        raise BuildError(f"unsupported file name in {where}: {name!r}")


def walk_tree(root: Path, *, skip=lambda parts, is_dir: False, dereference_files: bool = False,
              ) -> list[tuple[tuple[str, ...], bytes]]:
    """Read every regular file under ``root``; refuse links and special files."""
    root_real = Path(os.path.realpath(root))
    results: list[tuple[tuple[str, ...], bytes]] = []

    def visit(directory: Path, parts: tuple[str, ...]) -> None:
        with os.scandir(directory) as iterator:
            children = sorted(iterator, key=lambda entry: entry.name)
        for child in children:
            rel = parts + (child.name,)
            is_link = child.is_symlink() or getattr(child, "is_junction", lambda: False)()
            is_dir = child.is_dir(follow_symlinks=False)
            if skip(rel, is_dir):
                continue
            check_name(child.name, str(root))
            if is_link:
                if not dereference_files or is_dir:
                    raise BuildError(f"symbolic link refused: {'/'.join(rel)}")
                target = Path(os.path.realpath(child.path))
                try:
                    target.relative_to(root_real)
                except ValueError as exc:
                    raise BuildError(f"link leaves its tree: {'/'.join(rel)}") from exc
                if not target.is_file():
                    raise BuildError(f"link is not a regular file: {'/'.join(rel)}")
                results.append((rel, target.read_bytes()))
            elif is_dir:
                visit(Path(child.path), rel)
            elif child.is_file(follow_symlinks=False):
                results.append((rel, Path(child.path).read_bytes()))
            else:
                raise BuildError(f"special file refused: {'/'.join(rel)}")

    if not root.is_dir() or root.is_symlink():
        raise BuildError(f"directory required: {root}")
    visit(root, ())
    return results


def skip_python_noise(parts: tuple[str, ...], is_dir: bool) -> bool:
    name = parts[-1]
    return name == "__pycache__" or (not is_dir and name.endswith((".pyc", ".pyo")))


def skip_collection_noise(parts: tuple[str, ...], is_dir: bool) -> bool:
    # parts are relative to ansible_collections: <namespace>/<name>/<entry>...
    if skip_python_noise(parts, is_dir) or parts[-1] == ".git":
        return True
    return len(parts) == 3 and is_dir and parts[2] in ("tests", "docs")


# --------------------------------------------------------------------------- site validation

def validate_jobs(data) -> dict:
    if type(data) is not dict or set(data) != {"version", "service_user", "targets", "controls"}:
        raise BuildError("policy/jobs.json must contain exactly version, service_user, targets, controls")
    if type(data["version"]) is not int or data["version"] != 2:
        raise BuildError("policy/jobs.json version must be 2")
    user = data["service_user"]
    if type(user) is not str or not ID.fullmatch(user) or user == "root":
        raise BuildError("policy/jobs.json service_user must be a non-root identifier")
    targets = data["targets"]
    if type(targets) is not dict or not targets or len(targets) > 64:
        raise BuildError("policy/jobs.json needs 1..64 targets")
    hosts = []
    for key, value in targets.items():
        if not ID.fullmatch(key) or type(value) is not dict or set(value) != {"host", "os"}:
            raise BuildError(f"invalid target {key!r}")
        if (type(value["host"]) is not str or not ID.fullmatch(value["host"])
                or value["host"] in ("all", "ungrouped") or value["os"] not in PLATFORMS):
            raise BuildError(f"invalid target {key!r}")
        hosts.append(value["host"])
    if len(hosts) != len(set(hosts)):
        raise BuildError("inventory host aliases must be unique")
    controls = data["controls"]
    if type(controls) is not dict:
        raise BuildError("policy/jobs.json controls must be an object")
    for name, value in controls.items():
        if (type(value) is not dict or set(value) != {"tag", "os"} or CONTROLS.get(name) != value["tag"]
                or type(value["os"]) is not list or not value["os"]
                or any(item not in PLATFORMS for item in value["os"])):
            raise BuildError(f"control {name!r} has no reviewed remediation capability")
    return data


def _identifier_list(value, what: str) -> list[str]:
    if type(value) is not list or not value or any(
            type(item) is not str or not ID.fullmatch(item) for item in value):
        raise BuildError(f"invalid {what}")
    return value


def render_profiles(data, release_id: str, jobs: dict) -> dict:
    """Validate the profile catalog and bind its single release key to ``release_id``."""
    if type(data) is not dict or set(data) != {"releases"} or type(data["releases"]) is not dict:
        raise BuildError("policy/profiles.json must be {\"releases\": {...}}")
    if len(data["releases"]) != 1:
        raise BuildError("policy/profiles.json must describe exactly one release")
    key, release = next(iter(data["releases"].items()))
    if key not in (PLACEHOLDER, release_id):
        raise BuildError(f"profiles release key must be {PLACEHOLDER} or {release_id}")
    if type(release) is not dict or set(release) != {
            "inventory_profiles", "host_profiles", "section_profiles"}:
        raise BuildError("profiles release needs inventory_profiles, host_profiles, section_profiles")
    configured = {value["host"]: value["os"] for value in jobs["targets"].values()}
    inventories = release["inventory_profiles"]
    if type(inventories) is not dict or not inventories:
        raise BuildError("inventory_profiles must be a non-empty object")
    for name, profile in inventories.items():
        if (not ID.fullmatch(name) or type(profile) is not dict
                or set(profile) != {"platform", "aliases"} or profile["platform"] not in PLATFORMS):
            raise BuildError(f"invalid inventory profile {name!r}")
        for alias in _identifier_list(profile["aliases"], f"aliases of {name}"):
            if configured.get(alias) != profile["platform"]:
                raise BuildError(f"alias {alias!r} of profile {name!r} is not a jobs.json target "
                                 "of the same platform")
    hosts = release["host_profiles"]
    if type(hosts) is not dict:
        raise BuildError("host_profiles must be an object")
    for name, profile in hosts.items():
        if (not ID.fullmatch(name) or type(profile) is not dict
                or set(profile) != {"inventory_profile", "platform", "alias"}):
            raise BuildError(f"invalid host profile {name!r}")
        parent = inventories.get(profile["inventory_profile"])
        if (parent is None or parent["platform"] != profile["platform"]
                or profile["alias"] not in parent["aliases"]):
            raise BuildError(f"host profile {name!r} disagrees with its inventory profile")
    sections = release["section_profiles"]
    if type(sections) is not dict:
        raise BuildError("section_profiles must be an object")
    for name, profile in sections.items():
        if (not ID.fullmatch(name) or type(profile) is not dict or set(profile) != {
                "host_profile", "section", "tags", "gates", "disposition", "network_rules"}
                or profile["host_profile"] not in hosts):
            raise BuildError(f"invalid section profile {name!r}")
    return {"releases": {release_id: release}}


def validate_site(site: Path, release_id: str, *, allow_lab_ssh: bool = False,
                  allowed_keys: frozenset[str] = frozenset()):
    """Return (entries, jobs_bytes, profiles_bytes, warnings) for a site directory."""
    if not site.is_dir() or site.is_symlink():
        raise BuildError(f"site directory required: {site}")
    for child in sorted(site.iterdir()):
        if child.name in SITE_ROOT_IGNORED or child.name.upper().startswith("README"):
            continue
        if child.name not in ("inventory", "policy"):
            raise BuildError(f"unexpected entry in site directory: {child.name}")
    warnings: list[str] = []
    problems: list[str] = []

    def skip_site(parts, is_dir):
        return parts[-1] in (".gitkeep", ".gitignore") or (
            not is_dir and parts[-1].upper().startswith("README"))

    inventory_files = walk_tree(site / "inventory", skip=skip_site)
    entries: dict[str, bytes] = {}
    for parts, data in inventory_files:
        name = "inventory/" + "/".join(parts)
        if not parts[-1].endswith(SITE_EXTENSIONS):
            problems.append(f"{name}: extension not allowed (use {', '.join(SITE_EXTENSIONS)})")
            continue
        if len(data) > MAX_SITE_FILE:
            problems.append(f"{name}: larger than 1 MiB")
            continue
        problems.extend(scan_site_text(name, data, allow_lab_ssh=allow_lab_ssh,
                                       allowed_keys=allowed_keys))
        entries["payload/inventory/" + "/".join(parts)] = data
    if "payload/inventory/hosts.yml" not in entries:
        problems.append("inventory/hosts.yml is required")
    policy_files = dict(((parts[0], data) for parts, data in
                         walk_tree(site / "policy", skip=skip_site) if len(parts) == 1))
    if set(policy_files) != {"jobs.json", "profiles.json"}:
        problems.append("policy/ must contain exactly jobs.json and profiles.json")
    for name, data in policy_files.items():
        problems.extend(scan_site_text("policy/" + name, data, allow_lab_ssh=allow_lab_ssh,
                                       allowed_keys=allowed_keys))
    if problems:
        raise BuildError("site directory refused:\n  " + "\n  ".join(problems))
    jobs = validate_jobs(load_json(policy_files["jobs.json"], "policy/jobs.json"))
    profiles = render_profiles(load_json(policy_files["profiles.json"], "policy/profiles.json"),
                               release_id, jobs)
    text = "\n".join(data.decode("utf-8") for key, data in entries.items())
    for target in jobs["targets"].values():
        if not re.search(r"(?m)^\s*" + re.escape(target["host"]) + r"\s*:", text):
            warnings.append(f"host alias {target['host']} was not found in the inventory text")
    for platform, variable in (("ubuntu24", "cis_ubuntu_2404_sshd_allow_users"),
                               ("debian12", "cis_debian_12_sshd_allow_users")):
        if any(t["os"] == platform for t in jobs["targets"].values()):
            found = re.search(r"(?m)^\s*" + variable + r"\s*:\s*(\[\s*\])?\s*(#.*)?$", text)
            if not re.search(variable, text) or found and found.group(1):
                warnings.append(f"{variable} is empty or missing: CIS 5.1.4 will refuse to run")
    jobs_bytes = (json.dumps(jobs, sort_keys=True, indent=2) + "\n").encode("utf-8")
    profiles_bytes = (json.dumps(profiles, sort_keys=True, indent=2) + "\n").encode("utf-8")
    return entries, jobs_bytes, profiles_bytes, warnings


# --------------------------------------------------------------------------- project tree

def gateway_pin(wazuh: Path) -> dict[str, str]:
    """Hash the gateway sources and check the sealed-bootstrap pin."""
    hashes = {}
    for name in GATEWAY_FILES:
        path = wazuh / name
        if not path.is_file() or path.is_symlink():
            raise BuildError(f"gateway source missing: integration/wazuh/{name}")
        data = path.read_bytes()
        if b"\r" in data:
            raise BuildError(f"{name} contains CR characters; check out with LF line endings")
        hashes[name] = sha256_hex(data)
    first = (wazuh / "managed_job.py").read_bytes().split(b"\n", 1)[0]
    if first != b"#!/usr/bin/python3 -I":
        raise BuildError("managed_job.py shebang must be '#!/usr/bin/python3 -I'")
    pinned = re.search(rb'(?m)^BOOTSTRAP_SHA256 = "([0-9a-f]{64})"$',
                       (wazuh / "managed_job.py").read_bytes())
    if pinned is None or pinned.group(1).decode() != hashes["runtime_bootstrap.py"]:
        raise BuildError("runtime_bootstrap.py differs from the BOOTSTRAP_SHA256 pin in managed_job.py")
    return hashes


def project_entries(repo: Path) -> dict[str, bytes]:
    ansible = repo / "ansible"
    entries: dict[str, bytes] = {}
    config = ansible / "ansible.cfg"
    if not config.is_file() or config.is_symlink():
        raise BuildError("ansible/ansible.cfg is required")
    entries["payload/ansible/ansible.cfg"] = config.read_bytes()
    problems: list[str] = []
    for directory in ("playbooks", "roles"):
        for parts, data in walk_tree(ansible / directory, skip=skip_python_noise):
            name = "payload/ansible/" + directory + "/" + "/".join(parts)
            problems.extend(scan_project_bytes(name, data))
            entries[name] = data
    if problems:
        raise BuildError("project tree refused:\n  " + "\n  ".join(problems))
    return entries


def _files_json_is_pinned(collection: Path, listing_raw: bytes) -> bool:
    """When MANIFEST.json exists, FILES.json must match its file_manifest_file checksum."""
    manifest_path = collection / "MANIFEST.json"
    if not manifest_path.exists() and not manifest_path.is_symlink():
        return True
    if manifest_path.is_symlink() or not manifest_path.is_file():
        return False
    try:
        meta = load_json(manifest_path.read_bytes(), str(manifest_path))
    except BuildError:
        return False
    pinned = meta.get("file_manifest_file") if type(meta) is dict else None
    expected = pinned.get("chksum_sha256") if type(pinned) is dict else None
    return type(expected) is str and expected.lower() == sha256_hex(listing_raw)


def _collection_checksums(root: Path) -> dict[tuple[str, ...], str]:
    """Map every file listed in each installed collection's FILES.json to its sha256."""
    checksums: dict[tuple[str, ...], str] = {}
    for namespace in sorted(root.iterdir()):
        if not namespace.is_dir() or namespace.is_symlink() or namespace.name.endswith(".info"):
            continue
        for collection in sorted(namespace.iterdir()):
            files_json = collection / "FILES.json"
            if not collection.is_dir() or not files_json.is_file() or files_json.is_symlink():
                continue
            listing_raw = files_json.read_bytes()
            if not _files_json_is_pinned(collection, listing_raw):
                continue  # untrusted listing: its files fall back to the private-key guard
            listing = load_json(listing_raw, str(files_json))
            for item in listing.get("files", []) if type(listing) is dict else []:
                if (type(item) is dict and item.get("ftype") == "file"
                        and item.get("chksum_type") == "sha256"
                        and type(item.get("name")) is str and type(item.get("chksum_sha256")) is str):
                    parts = (namespace.name, collection.name, *item["name"].split("/"))
                    checksums[parts] = item["chksum_sha256"]
    return checksums


def collection_entries(collections: Path) -> dict[str, bytes]:
    root = collections / "ansible_collections"
    if not root.is_dir():
        raise BuildError("--collections must contain an ansible_collections directory")
    entries = {}
    upstream = _collection_checksums(root)
    for parts, data in walk_tree(root, skip=skip_collection_noise, dereference_files=True):
        # Files proven byte-identical to the collection's FILES.json are pinned upstream
        # content (module docs legitimately contain example PEM blocks). Anything else
        # must pass the private-key guard.
        expected = upstream.get(tuple(parts))
        if expected is None or expected != sha256_hex(data):
            if PEM_PRIVATE.search(data):
                raise BuildError("collection file contains private key material: " + "/".join(parts))
        entries["payload/collections/ansible_collections/" + "/".join(parts)] = data
    if not entries:
        raise BuildError("--collections contains no files after stripping tests and docs")
    return entries


def git_state(repo: Path) -> tuple[str | None, bool]:
    if not (repo / ".git").exists():
        return None, False
    try:
        head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True,
                              text=True, check=True, timeout=30).stdout.strip()
        dirty = bool(subprocess.run(
            ["git", "-C", str(repo), "status", "--porcelain", "--untracked-files=no"],
            capture_output=True, text=True, check=True, timeout=60).stdout.strip())
    except (OSError, subprocess.SubprocessError):
        return None, False
    return (head if re.fullmatch(r"[0-9a-f]{40,64}", head) else None), dirty


# --------------------------------------------------------------------------- bundle writing

def build_manifest(release_id: str, entries: dict[str, bytes], gateway: dict[str, str],
                   commit: str | None, dirty: bool, has_collections: bool) -> bytes:
    manifest = {
        "format": BUNDLE_FORMAT, "release_id": release_id, "ansible_core": REQUIRED_CORE,
        "source_commit": commit, "source_dirty": dirty, "has_collections": has_collections,
        "gateway_files": gateway,
        "files": {name: sha256_hex(data) for name, data in sorted(entries.items())},
    }
    return (json.dumps(manifest, sort_keys=True, indent=1) + "\n").encode("utf-8")


def write_tar(handle, entries: dict[str, bytes]) -> None:
    with gzip.GzipFile(filename="", mode="wb", fileobj=handle, mtime=FIXED_MTIME,
                       compresslevel=9) as stream:
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.GNU_FORMAT) as archive:
            for name in ["MANIFEST.json"] + sorted(key for key in entries if key != "MANIFEST.json"):
                data = entries[name]
                info = tarfile.TarInfo(name)
                info.size, info.mtime, info.mode = len(data), FIXED_MTIME, 0o644
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.type = tarfile.REGTYPE
                archive.addfile(info, io.BytesIO(data))


def self_check(path: Path) -> dict:
    """Re-open the finished bundle and prove it only holds hashed regular files."""
    members = links = 0
    with tarfile.open(path, "r:gz") as archive:
        names = set()
        manifest = None
        for member in archive:
            members += 1
            if member.issym() or member.islnk():
                links += 1
            if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE):
                raise BuildError("self-check: non-regular entry " + member.name)
            data = archive.extractfile(member).read()
            if member.name == "MANIFEST.json":
                manifest = json.loads(data)
            else:
                names.add(member.name)
                if manifest is None or manifest["files"].get(member.name) != sha256_hex(data):
                    raise BuildError("self-check: hash mismatch for " + member.name)
    if manifest is None or names != set(manifest["files"]):
        raise BuildError("self-check: manifest and archive disagree")
    return {"entries": members, "symlinks": links}


def build_bundle(repo_root: Path, site: Path, release_id: str, out_dir: Path, *,
                 collections: Path | None = None, allow_lab_ssh: bool = False,
                 allowed_keys: frozenset[str] = frozenset()) -> dict:
    validate_release_id(release_id)
    repo_root = repo_root.resolve()
    gateway = gateway_pin(repo_root / "integration" / "wazuh")
    entries = project_entries(repo_root)
    site_entries, jobs_bytes, profiles_bytes, warnings = validate_site(
        site, release_id, allow_lab_ssh=allow_lab_ssh, allowed_keys=allowed_keys)
    entries.update(site_entries)
    entries["policy/jobs.json"] = jobs_bytes
    entries["policy/profiles.json"] = profiles_bytes
    if collections is not None:
        entries.update(collection_entries(collections))
    else:
        warnings.append("no --collections given: the bundle carries no Ansible collections "
                        "(ansible.posix and community.general are required by the roles)")
    commit, dirty = git_state(repo_root)
    if dirty:
        warnings.append("tracked files have uncommitted changes; the bundle is not reproducible "
                        "from the recorded commit")
    manifest = build_manifest(release_id, entries, gateway, commit, dirty, collections is not None)
    archive = dict(entries)
    archive["MANIFEST.json"] = manifest

    out_dir.mkdir(parents=True, exist_ok=True)
    bundle = out_dir / (release_id + ".tar.gz")
    checksum = out_dir / (release_id + ".tar.gz.sha256")
    listing = out_dir / (release_id + ".manifest.txt")
    for path in (bundle, checksum, listing):
        if path.exists() or path.is_symlink():
            raise BuildError(f"refusing to overwrite {path}")
    partial = out_dir / (release_id + ".tar.gz.partial")
    try:
        with open(partial, "xb") as handle:
            write_tar(handle, archive)
        os.replace(partial, bundle)
    finally:
        partial.unlink(missing_ok=True)
    digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
    checksum.write_text(f"{digest}  {bundle.name}\n", encoding="ascii", newline="\n")
    manifest_data = json.loads(manifest)
    listing.write_text("".join(
        f"{manifest_data['files'][name]}  {len(entries[name]):>9}  {name}\n"
        for name in sorted(entries)), encoding="utf-8", newline="\n")
    stats = self_check(bundle)
    return {"release_id": release_id, "bundle": str(bundle), "sha256_file": str(checksum),
            "listing": str(listing), "bytes": bundle.stat().st_size, "sha256": digest,
            "entries": stats["entries"], "symlinks": stats["symlinks"], "warnings": warnings,
            "source_commit": commit}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--repo-root", type=Path, required=True,
                        help="project Git tree (contains ansible/ and integration/wazuh/)")
    parser.add_argument("--site", type=Path, required=True,
                        help="site directory (inventory/ and policy/) from the institution's repo")
    parser.add_argument("--release-id", required=True, help="new, never-used release identifier")
    parser.add_argument("--out", type=Path, required=True, help="output directory")
    parser.add_argument("--collections", type=Path,
                        help="directory holding ansible_collections/ (ansible-galaxy install -p)")
    parser.add_argument("--allow-lab-ssh-options", action="store_true",
                        help="lab only: accept StrictHostKeyChecking=no / UserKnownHostsFile=/dev/null")
    parser.add_argument("--allow-key", action="append", default=[], metavar="KEY",
                        help="accept a reviewed non-secret variable flagged as secret-like")
    args = parser.parse_args(argv)
    try:
        result = build_bundle(args.repo_root, args.site, args.release_id, args.out,
                              collections=args.collections, allow_lab_ssh=args.allow_lab_ssh_options,
                              allowed_keys=frozenset(args.allow_key))
    except (BuildError, OSError) as exc:
        print("build refused: " + str(exc), file=sys.stderr)
        return 2
    for warning in result.pop("warnings"):
        print("WARNING: " + warning, file=sys.stderr)
    for key in ("release_id", "bundle", "bytes", "sha256", "entries", "symlinks",
                "sha256_file", "listing", "source_commit"):
        print(f"{key}: {result[key]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
