"""Pure-function tests for the controller installer (no root, no Linux services needed)."""

import gzip
import hashlib
import importlib.util
import io
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
WAZUH = ROOT / "integration" / "wazuh"


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, WAZUH / filename)
    module = importlib.util.module_from_spec(spec)
    # managed_job imports the Linux-only pwd module. Stub it only while loading so
    # the stub never leaks into other test modules (patch.dict restores sys.modules).
    stub = {"pwd": types.SimpleNamespace()} if sys.platform == "win32" else {}
    with mock.patch.dict(sys.modules, stub):
        spec.loader.exec_module(module)
    return module


installer = load("install_controller_under_test", "install_controller.py")
builder = load("build_release_for_installer_test", "build_release.py")
manager = load("install_manager_under_test", "install_manager.py")
gateway = load("managed_job_for_installer_test", "managed_job.py")
prepare = load("prepare_isolated_runtime_for_installer_test", "prepare_isolated_runtime.py")


def make_archive(files, *, manifest_files=None, extra_members=(), manifest_first=True,
                 release_id="rel_1", gzip_it=True, manifest_override=None):
    """Build a tar.gz. ``files`` maps name to bytes; members in extra_members are raw TarInfos."""
    manifest = {"format": 1, "release_id": release_id, "ansible_core": "2.21.2",
                "source_commit": None, "source_dirty": False, "has_collections": True,
                "gateway_files": {name: "0" * 64 for name in installer.GATEWAY_FILES},
                "files": manifest_files if manifest_files is not None else
                {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}}
    manifest.update(manifest_override or {})
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as archive:
        def add(name, data):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        if manifest_first:
            add("MANIFEST.json", json.dumps(manifest).encode())
        for name, data in files.items():
            add(name, data)
        for info, data in extra_members:
            archive.addfile(info, io.BytesIO(data) if data is not None else None)
        if not manifest_first:
            add("MANIFEST.json", json.dumps(manifest).encode())
    payload = raw.getvalue()
    return gzip.compress(payload, mtime=0) if gzip_it else payload


GOOD = {
    "payload/ansible/ansible.cfg": b"[defaults]\n",
    "payload/inventory/hosts.yml": b"all:\n",
    "policy/jobs.json": json.dumps({"version": 2, "service_user": "ansible-wazuh",
                                    "targets": {"t": {"host": "h", "os": "ubuntu24"}},
                                    "controls": {}}).encode(),
    "policy/profiles.json": b'{"releases":{"rel_1":{}}}',
}


class Sha256FileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.bundle = self.tmp / "b.tar.gz"
        self.bundle.write_bytes(b"bundle bytes")
        self.digest = hashlib.sha256(b"bundle bytes").hexdigest()

    def check(self, text):
        sha = self.tmp / "b.sha256"
        sha.write_text(text)
        return installer.read_verified_bundle(self.bundle, sha)

    def test_accepts_sha256sum_and_bare_formats(self):
        for text in (f"{self.digest}  b.tar.gz\n", f"{self.digest} *b.tar.gz\n", self.digest + "\n",
                     self.digest.upper() + "  b.tar.gz\n"):
            with self.subTest(text=text):
                data, digest = self.check(text)
                self.assertEqual((data, digest), (b"bundle bytes", self.digest))

    def test_rejects_wrong_malformed_or_foreign_digests(self):
        for text in ("0" * 64 + "  b.tar.gz\n", "short\n", "", f"{self.digest}  other.tar.gz\n",
                     f"{self.digest}  b.tar.gz\n{self.digest}  b.tar.gz\n"):
            with self.subTest(text=text), self.assertRaises(installer.InstallError):
                self.check(text)

    def test_rejects_symlinked_or_missing_bundle(self):
        with self.assertRaises(installer.InstallError):
            installer.read_verified_bundle(self.tmp / "missing", self.tmp / "x")


class ExpectedDigestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.bundle = self.tmp / "b.tar.gz"
        self.bundle.write_bytes(b"bundle bytes")
        self.digest = hashlib.sha256(b"bundle bytes").hexdigest()

    def test_expected_digest_is_the_trust_anchor(self):
        data, digest = installer.read_verified_bundle(self.bundle, None, self.digest.upper())
        self.assertEqual((data, digest), (b"bundle bytes", self.digest))
        for bad in ("0" * 64, "short", ""):
            with self.subTest(bad=bad), self.assertRaises(installer.InstallError):
                installer.read_verified_bundle(self.bundle, None, bad)

    def test_shipped_file_cannot_override_a_mismatching_expected_digest(self):
        sha = self.tmp / "b.sha256"
        sha.write_text("0" * 64 + "\n")
        with self.assertRaises(installer.InstallError):
            installer.read_verified_bundle(self.bundle, sha, self.digest)

    def test_bundle_read_is_hard_bounded(self):
        with mock.patch.object(installer, "MAX_BUNDLE", 5), self.assertRaises(installer.InstallError):
            installer.read_verified_bundle(self.bundle, None, self.digest)

    def test_release_requires_expected_digest_and_release_id(self):
        parser = installer.build_parser()
        base = ["release", "--bundle", "b.tar.gz"]
        for argv in (base, base + ["--expect-sha256", "0" * 64], base + ["--expect-release-id", "x"]):
            with self.subTest(argv=argv), self.assertRaises(SystemExit), \
                    mock.patch("sys.stderr", io.StringIO()):
                parser.parse_args(argv)
        args = parser.parse_args(base + ["--expect-sha256", "0" * 64, "--expect-release-id", "x"])
        self.assertIsNone(args.sha256)


class MemberPathTests(unittest.TestCase):
    def test_safe_paths(self):
        self.assertEqual(installer.member_parts("MANIFEST.json"), ("MANIFEST.json",))
        self.assertEqual(installer.member_parts("payload/ansible/roles/r/tasks/main.yml")[0], "payload")

    def test_unsafe_paths(self):
        for name in ("/etc/passwd", "payload/../x", "payload/./x", "payload//x", "payload\\x",
                     "C:/x", "payload/a\0b", "", "other/x", "payload", "payload/" + "a/" * 40 + "f",
                     "payload/sp ace", "../payload/x", "policy/-x;rm"):
            with self.subTest(name=name), self.assertRaises(installer.InstallError):
                installer.member_parts(name)

    def test_only_paths_produced_by_the_builder_are_accepted(self):
        for name in ("payload/home/.ssh/config", "payload/plugins/x.py", "payload/runtime/bin/x",
                     "payload/ansible/hooks/x.yml", "payload/ansible/other.cfg",
                     "payload/collections/x/y", "policy/extra.json", "policy/jobs.json/x",
                     "payload/inventory", "payload/ansible/roles", "MANIFEST.json/x"):
            with self.subTest(name=name), self.assertRaises(installer.InstallError):
                installer.member_parts(name)
        for name in ("payload/ansible/ansible.cfg", "payload/ansible/playbooks/p.yml",
                     "payload/ansible/roles/r/tasks/main.yml", "payload/inventory/hosts.yml",
                     "payload/collections/ansible_collections/ns/col/meta/runtime.yml",
                     "policy/jobs.json", "policy/profiles.json"):
            with self.subTest(name=name):
                self.assertEqual(installer.member_parts(name), tuple(name.split("/")))

    def test_every_builder_output_path_is_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            (repo / "integration" / "wazuh").mkdir(parents=True)
            for name in builder.GATEWAY_FILES:
                shutil.copy2(WAZUH / name, repo / "integration" / "wazuh" / name)
            (repo / "ansible" / "playbooks").mkdir(parents=True)
            (repo / "ansible" / "roles" / "r").mkdir(parents=True)
            (repo / "ansible" / "ansible.cfg").write_text("[defaults]\n")
            (repo / "ansible" / "playbooks" / "p.yml").write_text("---\n")
            (repo / "ansible" / "roles" / "r" / "m.yml").write_text("---\n")
            col = Path(tmp) / "col" / "ansible_collections" / "ns" / "c" / "meta"
            col.mkdir(parents=True)
            (col / "runtime.yml").write_text("---\n")
            site = Path(tmp) / "site"
            shutil.copytree(WAZUH / "site.example", site)
            result = builder.build_bundle(repo, site, "rel_8", Path(tmp) / "out",
                                          collections=Path(tmp) / "col")
            with tarfile.open(result["bundle"], "r:gz") as archive:
                for member in archive:
                    installer.member_parts(member.name)


class InspectBundleTests(unittest.TestCase):
    def test_good_bundle(self):
        result = installer.inspect_bundle(make_archive(GOOD))
        self.assertEqual(result.manifest["release_id"], "rel_1")
        self.assertEqual(set(result.policy_files), {"policy/jobs.json", "policy/profiles.json"})
        self.assertEqual(result.names, sorted(GOOD))

    def rejects(self, data, message=None):
        with self.assertRaises(installer.InstallError) as caught:
            installer.inspect_bundle(data)
        if message:
            self.assertIn(message, str(caught.exception))

    def link(self, kind, name="payload/ansible/roles/evil", target="/etc/passwd"):
        info = tarfile.TarInfo(name)
        info.type = kind
        info.linkname = target
        return info, None

    def test_links_devices_and_fifos_are_refused(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE):
            with self.subTest(kind=kind):
                self.rejects(make_archive(GOOD, extra_members=[self.link(kind)]), "refused")

    def test_unsafe_names_are_refused(self):
        for name in ("/abs/path", "payload/../../etc/cron.d/x", "payload\\evil", "other/x"):
            with self.subTest(name=name):
                files = dict(GOOD)
                files[name] = b"x"
                self.rejects(make_archive(files, manifest_files={
                    **{n: hashlib.sha256(d).hexdigest() for n, d in GOOD.items()}}))

    def test_tampered_extra_missing_and_misordered_content(self):
        tampered = dict(GOOD)
        tampered["payload/inventory/hosts.yml"] = b"all: evil\n"
        manifest = {name: hashlib.sha256(data).hexdigest() for name, data in GOOD.items()}
        self.rejects(make_archive(tampered, manifest_files=manifest), "hash mismatch")
        extra = dict(GOOD, **{"payload/ansible/roles/extra.yml": b"x"})
        self.rejects(make_archive(extra, manifest_files=manifest), "not in manifest")
        missing = {k: v for k, v in GOOD.items() if k != "policy/profiles.json"}
        self.rejects(make_archive(missing, manifest_files=manifest), "different files")
        self.rejects(make_archive(GOOD, manifest_first=False), "first entry")

    def test_duplicate_entries_are_refused(self):
        info = tarfile.TarInfo("payload/ansible/ansible.cfg")
        info.size = 3
        self.rejects(make_archive(GOOD, extra_members=[(info, b"abc")]), "duplicate")

    def test_required_files_and_manifest_shape(self):
        for name in ("payload/inventory/hosts.yml", "policy/jobs.json"):
            files = {k: v for k, v in GOOD.items() if k != name}
            self.rejects(make_archive(files), "lacks")
        self.rejects(make_archive(GOOD, manifest_override={"format": 2}), "manifest")
        self.rejects(make_archive(GOOD, manifest_override={"release_id": "../x"}), "release id")
        self.rejects(make_archive(GOOD, manifest_override={"ansible_core": "2.0"}), "manifest")

    def test_size_limits(self):
        with mock.patch.object(installer, "MAX_FILE", 5):
            self.rejects(make_archive(GOOD), "too large")
        with mock.patch.object(installer, "MAX_TOTAL", 10):
            self.rejects(make_archive(GOOD), "size limit")
        with mock.patch.object(installer, "MAX_MEMBERS", 2):
            self.rejects(make_archive(GOOD), "too many")

    def test_oversized_pax_headers_are_refused(self):
        raw = io.BytesIO()
        files = dict(GOOD)
        manifest = {"format": 1, "release_id": "rel_1", "ansible_core": "2.21.2",
                    "source_commit": None, "source_dirty": False, "has_collections": True,
                    "gateway_files": {name: "0" * 64 for name in installer.GATEWAY_FILES},
                    "files": {n: hashlib.sha256(d).hexdigest() for n, d in files.items()}}
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
            body = json.dumps(manifest).encode()
            info = tarfile.TarInfo("MANIFEST.json")
            info.size = len(body)
            archive.addfile(info, io.BytesIO(body))
            for name, data in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                if name == "policy/jobs.json":
                    info.pax_headers = {"comment": "x" * 20000}
                archive.addfile(info, io.BytesIO(data))
        self.rejects(gzip.compress(raw.getvalue(), mtime=0), "extended headers")

    def test_not_a_gzip_tar(self):
        self.rejects(b"not an archive", "readable")
        self.rejects(make_archive(GOOD, gzip_it=False), "readable")


class ExtractionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_extracts_only_payload_with_verified_content(self):
        data = make_archive(GOOD)
        manifest = installer.inspect_bundle(data).manifest
        destination = self.tmp / "payload"
        count = installer.extract_payload(data, destination, manifest)
        self.assertEqual(count, 2)
        self.assertEqual((destination / "ansible" / "ansible.cfg").read_bytes(), b"[defaults]\n")
        self.assertEqual((destination / "inventory" / "hosts.yml").read_bytes(), b"all:\n")
        self.assertFalse((self.tmp / "policy").exists())
        self.assertEqual({p.name for p in destination.iterdir()}, {"ansible", "inventory"})
        if sys.platform != "win32":
            self.assertEqual((destination / "ansible" / "ansible.cfg").stat().st_mode & 0o777, 0o644)
            self.assertEqual((destination / "ansible").stat().st_mode & 0o777, 0o755)

    def test_refuses_existing_destination(self):
        data = make_archive(GOOD)
        manifest = installer.inspect_bundle(data).manifest
        (self.tmp / "payload").mkdir()
        with self.assertRaises(installer.InstallError):
            installer.extract_payload(data, self.tmp / "payload", manifest)

    def test_detects_content_that_differs_from_manifest_during_extraction(self):
        data = make_archive(GOOD)
        manifest = dict(installer.inspect_bundle(data).manifest)
        manifest["files"] = dict(manifest["files"], **{"payload/ansible/ansible.cfg": "1" * 64})
        with self.assertRaises(installer.InstallError):
            installer.extract_payload(data, self.tmp / "payload", manifest)

    def test_end_to_end_with_the_real_builder(self):
        repo = self.tmp / "repo"
        (repo / "integration" / "wazuh").mkdir(parents=True)
        for name in builder.GATEWAY_FILES:
            shutil.copy2(WAZUH / name, repo / "integration" / "wazuh" / name)
        (repo / "ansible" / "playbooks").mkdir(parents=True)
        (repo / "ansible" / "roles" / "r").mkdir(parents=True)
        (repo / "ansible" / "ansible.cfg").write_text("[defaults]\n")
        (repo / "ansible" / "playbooks" / "p.yml").write_text("---\n")
        (repo / "ansible" / "roles" / "r" / "m.yml").write_text("---\n")
        site = self.tmp / "site"
        shutil.copytree(WAZUH / "site.example", site)
        result = builder.build_bundle(repo, site, "rel_9", self.tmp / "out")
        data, digest = installer.read_verified_bundle(Path(result["bundle"]), Path(result["sha256_file"]))
        self.assertEqual(digest, result["sha256"])
        inspection = installer.inspect_bundle(data)
        self.assertEqual(inspection.manifest["release_id"], "rel_9")
        installer.check_gateway_files(inspection.manifest, repo / "integration" / "wazuh")
        destination = self.tmp / "extracted"
        installer.extract_payload(data, destination, inspection.manifest)
        self.assertTrue((destination / "inventory" / "hosts.yml").is_file())
        self.assertTrue((destination / "ansible" / "roles" / "r" / "m.yml").is_file())
        policy = installer.render_policy(inspection.policy_files["policy/jobs.json"], "rel_9")
        self.assertEqual(policy["release_id"], "rel_9")


class GatewayContractTests(unittest.TestCase):
    def test_identifier_grammar_matches_the_gateway_in_every_tool(self):
        for module in (installer, builder):
            self.assertEqual(module.ID.pattern, gateway.ID.pattern)
        self.assertEqual(installer.TOP_LEVEL, ("payload", "policy"))

    def test_gateway_file_lists_agree(self):
        self.assertEqual(installer.GATEWAY_FILES, builder.GATEWAY_FILES)
        for name in installer.GATEWAY_FILES + installer.CONTROLLER_TOOLS:
            self.assertTrue((WAZUH / name).is_file(), name)
        self.assertTrue(set(prepare.MANAGED_HELPERS) <= set(installer.GATEWAY_FILES))
        self.assertIn("runtime_bootstrap.py", installer.GATEWAY_FILES)

    def test_paths_match_the_gateway_constants(self):
        self.assertEqual(installer.ENTRYPOINT, gateway.ENTRYPOINT)
        self.assertEqual(installer.POLICY_PATH, gateway.POLICY_PATH)
        self.assertEqual(installer.DEPLOYMENT_LOCK, gateway.DEPLOYMENT_LOCK)
        self.assertEqual(installer.RELEASES_ROOT, gateway.RELEASES_ROOT)
        self.assertEqual(installer.ACTIVATION_DIR, gateway.ACTIVATION_DIR)
        self.assertEqual(installer.APPROVAL_DIR, gateway.APPROVAL_DIR)
        self.assertEqual(installer.STATE_DIR, gateway.STATE_DIR)
        self.assertEqual(installer.RUNTIME_TMP, gateway.LOCAL_TEMP)
        self.assertEqual(installer.EVENT_LOG, gateway.EVENT_LOG)
        self.assertEqual(installer.REQUIRED_CORE, prepare.REQUIRED_CORE)

    def test_rendered_policy_has_exactly_the_gateway_schema_and_release_paths(self):
        policy = installer.render_policy(GOOD["policy/jobs.json"], "rel_1")
        self.assertEqual(set(policy), {"version", "release_id", "ansible_root", "ansible_bin_dir",
                                       "inventory", "service_user", "targets", "controls"})
        release = gateway.RELEASES_ROOT / "rel_1" / "payload"
        self.assertEqual(policy["ansible_root"], str(release / "ansible"))
        self.assertEqual(policy["ansible_bin_dir"], str(release / "runtime" / "bin"))
        self.assertEqual(policy["inventory"], str(release / "inventory" / "hosts.yml"))
        with self.assertRaises(installer.InstallError):
            installer.render_policy(b'{"version": 2}', "rel_1")
        with self.assertRaises(installer.InstallError):
            installer.render_policy(GOOD["policy/jobs.json"], "../x")

    def test_gateway_file_check(self):
        directory = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, directory, True)
        for name in installer.GATEWAY_FILES:
            shutil.copy2(WAZUH / name, directory / name)
        manifest = {"gateway_files": {name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
                                      for name in installer.GATEWAY_FILES}}
        installer.check_gateway_files(manifest, directory)
        (directory / "managed_job.py").write_bytes(b"changed")
        with self.assertRaises(installer.InstallError):
            installer.check_gateway_files(manifest, directory)

    def test_release_id_validation(self):
        self.assertEqual(installer.validate_release_id("lab_v2"), "lab_v2")
        for value in ("", "../x", "a" * 64, "9x", None):
            with self.subTest(value=value), self.assertRaises(installer.InstallError):
                installer.validate_release_id(value)

    def test_help_exits_cleanly(self):
        with self.assertRaises(SystemExit) as caught, mock.patch("sys.stdout", io.StringIO()):
            installer.build_parser().parse_args(["--help"])
        self.assertEqual(caught.exception.code, 0)


CONF = """<ossec_config>
  <client><server><address>10.0.0.1</address></server></client>
  <!-- <location>/var/log/ansible-wazuh-jobs.jsonl</location> -->
</ossec_config>

<ossec_config>
  <localfile><log_format>syslog</log_format><location>/var/log/syslog</location></localfile>
</ossec_config>
"""


class OssecMergeTests(unittest.TestCase):
    snippet = (WAZUH / "config" / "ansible_job_localfile.xml").read_text()

    def test_inserts_inside_the_last_block_and_ignores_comments(self):
        merged, changed = installer.merge_ossec_block(CONF, self.snippet, installer.LOCALFILE_PRESENT)
        self.assertTrue(changed)
        self.assertEqual(merged.count("/var/log/ansible-wazuh-jobs.jsonl</location>"), 2)  # + comment
        self.assertLess(merged.rfind("<localfile>"), merged.rfind("</ossec_config>"))
        self.assertTrue(merged.rstrip().endswith("</ossec_config>"))
        installer.validate_ossec_xml(merged)

    def test_is_idempotent(self):
        merged, _ = installer.merge_ossec_block(CONF, self.snippet, installer.LOCALFILE_PRESENT)
        again, changed = installer.merge_ossec_block(merged, self.snippet, installer.LOCALFILE_PRESENT)
        self.assertFalse(changed)
        self.assertEqual(again, merged)

    def test_wraps_when_no_block_exists(self):
        merged, changed = installer.merge_ossec_block("<!-- empty -->\n", self.snippet,
                                                      installer.LOCALFILE_PRESENT)
        self.assertTrue(changed)
        self.assertIn("<ossec_config>", merged)
        installer.validate_ossec_xml(merged)

    def test_xml_validation(self):
        installer.validate_ossec_xml('<?xml version="1.0"?>\n' + CONF)
        with self.assertRaises(installer.InstallError):
            installer.validate_ossec_xml("<ossec_config><oops></ossec_config>")

    def test_manager_command_block_merge(self):
        command = (WAZUH / "config" / "ansible_job_command.xml").read_text()
        merged, changed = manager.merge_block(CONF, command, manager.COMMAND_PRESENT)
        self.assertTrue(changed)
        manager.validate_xml(merged)
        again, changed = manager.merge_block(merged, command, manager.COMMAND_PRESENT)
        self.assertFalse(changed)
        self.assertEqual(again.count("<name>ansible-job</name>"), 1)
        self.assertEqual(re.findall(r"<executable>([^<]+)", merged), ["ansible-job"])


class FakeManager(manager.Target):
    """Simulates the few shell commands Target.write issues; records every argv."""

    def __init__(self, attributes=None, fail_on=None):
        super().__init__(None, False)
        self.calls, self.attrs, self.fail_on = [], attributes or {}, fail_on

    def run(self, argv, *, data=None, check=True):
        self.calls.append(list(argv))
        done = subprocess.CompletedProcess(argv, 0, b"", b"")
        if argv[0] == "stat":
            if argv[-1] in self.attrs:
                return subprocess.CompletedProcess(argv, 0, self.attrs[argv[-1]].encode(), b"")
            return subprocess.CompletedProcess(argv, 1, b"", b"")
        if argv[0] == "mktemp":
            return subprocess.CompletedProcess(argv, 0, (argv[2] + "/.ansible-job.AbC123\n").encode(), b"")
        if self.fail_on and argv[0] == self.fail_on:
            raise OSError("simulated failure")
        return done


class ManagerWriteTests(unittest.TestCase):
    def test_uses_unpredictable_temp_and_preserves_existing_attributes(self):
        target = FakeManager({"/var/ossec/etc/ossec.conf": "root:wazuh 640 regular file"})
        target.write("/var/ossec/etc/ossec.conf", b"data", "660")
        names = [call[0] for call in target.calls]
        self.assertEqual(names, ["stat", "mktemp", "sh", "chown", "chmod", "mv"])
        self.assertEqual(target.calls[1], ["mktemp", "-p", "/var/ossec/etc", ".ansible-job.XXXXXX"])
        temporary = "/var/ossec/etc/.ansible-job.AbC123"
        self.assertEqual(target.calls[3], ["chown", "-h", "root:wazuh", temporary])
        self.assertEqual(target.calls[4], ["chmod", "640", temporary])
        self.assertEqual(target.calls[5], ["mv", "-f", temporary, "/var/ossec/etc/ossec.conf"])
        self.assertFalse(any(".ansible-job.tmp" in " ".join(call) for call in target.calls))

    def test_new_file_gets_wazuh_defaults_and_backup_copies_the_original_attributes(self):
        target = FakeManager()
        target.write("/var/ossec/etc/rules/r.xml", b"x", "660")
        self.assertEqual(target.calls[3][:3], ["chown", "-h", "wazuh:wazuh"])
        self.assertEqual(target.calls[4][:2], ["chmod", "660"])
        target = FakeManager({"/var/ossec/etc/ossec.conf": "root:wazuh 640 regular file"})
        target.write("/var/ossec/etc/ossec.conf.bak", b"x", "660", like="/var/ossec/etc/ossec.conf")
        self.assertEqual(target.calls[3][:3], ["chown", "-h", "root:wazuh"])

    def test_refuses_symlinked_target_and_cleans_temp_on_failure(self):
        target = FakeManager({"/p/f": "root:wazuh 640 symbolic link"})
        with self.assertRaises(manager.ManagerError):
            target.write("/p/f", b"x", "660")
        target = FakeManager(fail_on="chmod")
        with self.assertRaises(OSError):
            target.write("/p/f", b"x", "660")
        self.assertEqual(target.calls[-1], ["rm", "-f", "/p/.ansible-job.AbC123"])

    def test_install_rolls_back_on_os_errors_too(self):
        events = []

        class Recording(manager.Target):
            def __init__(self):
                super().__init__(None, False)

            def read(self, path):
                return {"/var/ossec/etc/ossec.conf": CONF}.get(path)

            def write(self, path, data, mode, *, like=None):
                events.append((path, data))
                if path.endswith("ossec.conf") and b"ansible-job" in data:
                    raise OSError("disk full")

            def run(self, argv, *, data=None, check=True):
                events.append(tuple(argv))
                return subprocess.CompletedProcess(argv, 0, b"", b"")

        with mock.patch("sys.stdout", io.StringIO()), mock.patch("sys.stderr", io.StringIO()), \
                self.assertRaises(OSError):
            manager.install(Recording(), WAZUH / "config", restart=False)
        self.assertIn(("/var/ossec/etc/ossec.conf", CONF.encode()), events)
        self.assertIn(("rm", "-f", "/var/ossec/etc/rules/ansible_job_rules.xml"), events)


class GenerateSshKeyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.ssh = self.tmp / "ssh"
        self.ssh.mkdir()
        patch = mock.patch.multiple(installer, SSH_DIR=self.ssh, SSH_KEY=self.ssh / "id_rsa")
        patch.start()
        self.addCleanup(patch.stop)
        self.scratch_dirs = []

    def ctx(self):
        ctx = installer.Ctx(False)

        def fake_run(argv, **kwargs):
            key = Path(argv[argv.index("-f") + 1])
            self.scratch_dirs.append(key.parent)
            self.assertFalse(str(key).startswith(str(self.ssh)))  # never generated inside SSH_DIR
            key.write_bytes(b"PRIVATE")
            Path(str(key) + ".pub").write_bytes(b"ssh-ed25519 AAAA test\n")
            return subprocess_ok
        subprocess_ok = installer.subprocess.CompletedProcess([], 0)
        ctx.run = fake_run
        return ctx

    def test_installs_both_files_from_a_temporary_directory_and_cleans_up(self):
        with mock.patch("sys.stdout", io.StringIO()) as out:
            installer.generate_ssh_keypair(self.ctx(), None, None)
        self.assertEqual((self.ssh / "id_rsa").read_bytes(), b"PRIVATE")
        self.assertEqual((self.ssh / "id_rsa.pub").read_bytes(), b"ssh-ed25519 AAAA test\n")
        self.assertIn("ssh-ed25519 AAAA test", out.getvalue())
        self.assertNotIn("PRIVATE", out.getvalue())
        self.assertFalse(self.scratch_dirs[0].exists())

    def test_refuses_when_either_file_exists(self):
        (self.ssh / "id_rsa.pub").write_bytes(b"old")
        with self.assertRaises(installer.InstallError):
            installer.generate_ssh_keypair(self.ctx(), None, None)
        self.assertEqual(self.scratch_dirs, [])
        self.assertEqual((self.ssh / "id_rsa.pub").read_bytes(), b"old")

    @unittest.skipIf(sys.platform == "win32" or not hasattr(__import__("os"), "O_NOFOLLOW"),
                     "needs POSIX symlinks and O_NOFOLLOW")
    def test_does_not_follow_a_planted_symlink(self):
        victim = self.tmp / "victim"
        victim.write_bytes(b"keep")
        (self.ssh / "id_rsa.pub").symlink_to(victim)
        with self.assertRaises(installer.InstallError):
            installer.generate_ssh_keypair(self.ctx(), None, None)
        self.assertEqual(victim.read_bytes(), b"keep")
        self.assertFalse((self.ssh / "id_rsa").exists())

    @unittest.skipIf(sys.platform == "win32", "needs POSIX symlinks and O_NOFOLLOW")
    def test_exclusive_writer_refuses_a_symlink_created_after_the_check(self):
        victim = self.tmp / "victim"
        victim.write_bytes(b"keep")
        (self.ssh / "id_rsa").symlink_to(victim)
        with self.assertRaises(OSError):
            installer._write_new_file(self.ssh / "id_rsa", [b"x"], 0o600, None, None)
        self.assertEqual(victim.read_bytes(), b"keep")

    @unittest.skipIf(sys.platform == "win32", "needs POSIX symlinks and O_NOFOLLOW")
    def test_directory_fix_never_follows_a_symlink(self):
        real = self.tmp / "real"
        real.mkdir()
        link = self.tmp / "link"
        link.symlink_to(real, target_is_directory=True)
        with self.assertRaises(OSError):
            installer._fix_directory(link, link.lstat(), 0o700, None)


class UtilityTests(unittest.TestCase):
    def test_source_version_parse(self):
        self.assertEqual(installer.source_version("__version__ = '2.21.2'\n"), "2.21.2")
        self.assertIsNone(installer.source_version("x = 1"))


if __name__ == "__main__":
    unittest.main()
