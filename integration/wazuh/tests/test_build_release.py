"""Contract tests for the release bundle builder (stdlib only, no root needed)."""

import hashlib
import importlib.util
import json
import os
import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
WAZUH = ROOT / "integration" / "wazuh"
SPEC = importlib.util.spec_from_file_location("build_release_under_test", WAZUH / "build_release.py")
build = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build)


def symlink_or_skip(testcase, link: Path, target: Path, directory: bool = False) -> None:
    try:
        os.symlink(target, link, target_is_directory=directory)
    except (OSError, NotImplementedError):
        testcase.skipTest("symbolic links are not available in this environment")


class BuilderCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="build_release_test_"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.repo = self.tmp / "repo"
        (self.repo / "integration" / "wazuh").mkdir(parents=True)
        for name in build.GATEWAY_FILES:
            shutil.copy2(WAZUH / name, self.repo / "integration" / "wazuh" / name)
        ansible = self.repo / "ansible"
        (ansible / "playbooks").mkdir(parents=True)
        (ansible / "roles" / "demo" / "tasks").mkdir(parents=True)
        (ansible / "ansible.cfg").write_text("[defaults]\nbecome = True\n")
        (ansible / "playbooks" / "demo.yml").write_text("---\n- hosts: all\n  tasks: []\n")
        (ansible / "roles" / "demo" / "tasks" / "main.yml").write_text("---\n- ping:\n")
        self.site = self.tmp / "site"
        shutil.copytree(WAZUH / "site.example", self.site)
        self.out = self.tmp / "out"

    def build(self, release_id="rel_1", **kwargs):
        return build.build_bundle(self.repo, self.site, release_id, self.out, **kwargs)

    def names(self, result):
        with tarfile.open(result["bundle"], "r:gz") as archive:
            return {member.name for member in archive}

    def refused(self, message=None, **kwargs):
        with self.assertRaises(build.BuildError) as caught:
            self.build(**kwargs)
        if message:
            self.assertIn(message, str(caught.exception))


class ReleaseIdTests(unittest.TestCase):
    def test_gateway_grammar(self):
        for value in ("lab_v2", "A", "a.b-c_d", "x" * 64):
            self.assertEqual(build.validate_release_id(value), value)
        # "a" * 64 is a well-formed identifier but also a hex digest: refused like the gateway does.
        for value in ("", "1abc", "has space", "a/b", "../x", "x" * 65, "a" * 64, "é", None):
            with self.subTest(value=value), self.assertRaises(build.BuildError):
                build.validate_release_id(value)


class BuildTests(BuilderCase):
    def test_clean_build_layout_and_manifest(self):
        result = self.build()
        names = self.names(result)
        self.assertIn("MANIFEST.json", names)
        self.assertIn("payload/ansible/ansible.cfg", names)
        self.assertIn("payload/ansible/roles/demo/tasks/main.yml", names)
        self.assertIn("payload/inventory/hosts.yml", names)
        self.assertIn("payload/inventory/group_vars/ubuntu_2404.yml", names)
        self.assertIn("policy/jobs.json", names)
        self.assertEqual(result["symlinks"], 0)
        self.assertEqual(result["entries"], len(names))
        with tarfile.open(result["bundle"], "r:gz") as archive:
            manifest = json.load(archive.extractfile("MANIFEST.json"))
            profiles = json.load(archive.extractfile("policy/profiles.json"))
            first = archive.getmembers()[0]
        self.assertEqual(first.name, "MANIFEST.json")
        self.assertEqual(manifest["release_id"], "rel_1")
        self.assertEqual(set(manifest["gateway_files"]), set(build.GATEWAY_FILES))
        self.assertEqual(set(profiles["releases"]), {"rel_1"})
        digest = hashlib.sha256(Path(result["bundle"]).read_bytes()).hexdigest()
        self.assertEqual(Path(result["sha256_file"]).read_text().split()[0], digest)
        self.assertEqual(result["sha256"], digest)

    def test_bundle_is_deterministic(self):
        first = self.build()
        shutil.rmtree(self.out)
        os.utime(self.site / "policy" / "jobs.json", (1, 1))  # mtimes must not matter
        second = self.build()
        self.assertEqual(first["sha256"], second["sha256"])
        self.assertEqual(Path(first["bundle"]).read_bytes(), Path(second["bundle"]).read_bytes())

    def test_members_use_fixed_metadata(self):
        result = self.build()
        with tarfile.open(result["bundle"], "r:gz") as archive:
            for member in archive:
                self.assertEqual((member.mtime, member.uid, member.gid, member.mode),
                                 (0, 0, 0, 0o644), member.name)
                self.assertEqual(member.type, tarfile.REGTYPE)

    def test_refuses_to_overwrite_outputs(self):
        self.build()
        self.refused("refusing to overwrite")

    def test_invalid_release_id_is_rejected_before_any_output(self):
        self.refused("release id", release_id="../evil")
        self.assertFalse(self.out.exists())

    def test_bootstrap_pin_mismatch_is_rejected(self):
        path = self.repo / "integration" / "wazuh" / "runtime_bootstrap.py"
        path.write_bytes(path.read_bytes() + b"# drift\n")
        self.refused("BOOTSTRAP_SHA256")

    def test_crlf_gateway_source_is_rejected(self):
        path = self.repo / "integration" / "wazuh" / "execution_state.py"
        path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
        self.refused("CR characters")

    def test_private_key_in_project_tree_is_rejected(self):
        marker = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
        (self.repo / "ansible" / "roles" / "demo" / "tasks" / "key.yml").write_text(marker)
        self.refused("private key")


class SecretAndStructureTests(BuilderCase):
    def inventory_file(self, name, text):
        path = self.site / "inventory" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def test_private_key_material_is_rejected(self):
        self.inventory_file("group_vars/leak.yml", "x: |\n  -----BEGIN " + "RSA PRIVATE KEY-----\n")
        self.refused("private key")

    def test_plaintext_connection_passwords_are_rejected(self):
        for text in ("ansible_password: hunter2\n", "ansible_become_password: x\n",
                     "ansible_ssh_pass: x\n", "h ansible_sudo_pass=x\n"):
            with self.subTest(text=text):
                self.inventory_file("group_vars/leak.yml", text)
                self.refused("password variable")
                shutil.rmtree(self.out, ignore_errors=True)

    def test_vault_content_is_rejected(self):
        self.inventory_file("group_vars/vault.yml", "secret: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n")
        self.refused("vault")

    def test_secret_like_keys_need_review(self):
        self.inventory_file("group_vars/token.yml", "api_token: abcdef123456\n")
        self.refused("secret-like key")
        shutil.rmtree(self.out, ignore_errors=True)
        self.build(allowed_keys=frozenset({"api_token"}))

    def test_benign_secret_named_flags_pass(self):
        self.inventory_file("group_vars/flags.yml",
                            "cis_ubuntu_2404_5_2_4_sudo_password: false\n"
                            "retries_password_max: 5\n"
                            "token_service: \"{{ lookup_value }}\"\n")
        self.build()

    def test_ssh_key_path_is_pinned(self):
        self.inventory_file("group_vars/key.yml", "ansible_ssh_private_key_file: ~/.ssh/id_rsa\n")
        self.refused("ansible_ssh_private_key_file must be")

    def test_json_quoted_key_file_and_password_variables_are_checked(self):
        self.inventory_file("group_vars/key.json",
                            '{"ansible_ssh_private_key_file": "/home/x/.ssh/id_rsa"}\n')
        self.refused("ansible_ssh_private_key_file must be")
        shutil.rmtree(self.out, ignore_errors=True)
        self.inventory_file("group_vars/key.json", '{"ansible_password": "hunter2"}\n')
        self.refused("password variable")
        shutil.rmtree(self.out, ignore_errors=True)
        self.inventory_file("group_vars/key.json",
                            '{"ansible_ssh_private_key_file": "/var/lib/ansible-wazuh/ssh/id_rsa"}\n')
        self.build()

    def test_insecure_host_key_options_need_lab_flag(self):
        self.inventory_file("group_vars/ssh.yml",
                            "ansible_ssh_common_args: -o StrictHostKeyChecking=no\n")
        self.refused("insecure SSH")
        shutil.rmtree(self.out, ignore_errors=True)
        self.build(allow_lab_ssh=True)

    def test_unexpected_files_and_extensions_are_rejected(self):
        (self.site / "extras").mkdir()
        self.refused("unexpected entry")
        shutil.rmtree(self.site / "extras")
        shutil.rmtree(self.out, ignore_errors=True)
        self.inventory_file("id_rsa", "not a key but wrong extension\n")
        self.refused("extension not allowed")

    def test_binary_files_are_rejected(self):
        (self.site / "inventory" / "blob.yml").write_bytes(b"\x00\x01\x02")
        self.refused("binary")

    def test_symlinks_in_site_are_rejected(self):
        symlink_or_skip(self, self.site / "inventory" / "link.yml", self.site / "inventory" / "hosts.yml")
        self.refused("symbolic link")

    def test_symlinks_in_project_are_rejected(self):
        symlink_or_skip(self, self.repo / "ansible" / "roles" / "demo" / "tasks" / "l.yml",
                        self.repo / "ansible" / "ansible.cfg")
        self.refused("symbolic link")

    def test_missing_inventory_or_policy_is_rejected(self):
        (self.site / "inventory" / "hosts.yml").unlink()
        self.refused("hosts.yml is required")

    def test_policy_alias_must_match_jobs_targets(self):
        path = self.site / "policy" / "profiles.json"
        profiles = json.loads(path.read_text())
        release = profiles["releases"]["@RELEASE_ID@"]
        release["inventory_profiles"]["ubuntu_staging"]["aliases"].append("not-a-target")
        path.write_text(json.dumps(profiles))
        self.refused("not a jobs.json target")

    def test_profiles_release_key_must_be_placeholder_or_release(self):
        path = self.site / "policy" / "profiles.json"
        profiles = json.loads(path.read_text())
        profiles["releases"] = {"other_release": profiles["releases"]["@RELEASE_ID@"]}
        path.write_text(json.dumps(profiles))
        self.refused("profiles release key")

    def test_jobs_policy_rejects_unreviewed_controls_and_root(self):
        path = self.site / "policy" / "jobs.json"
        jobs = json.loads(path.read_text())
        jobs["controls"]["cron_hourly"]["tag"] = "cis_5_1_2"
        path.write_text(json.dumps(jobs))
        self.refused("reviewed remediation")
        jobs["controls"]["cron_hourly"]["tag"] = "cis_2_4_1_3"
        jobs["service_user"] = "root"
        path.write_text(json.dumps(jobs))
        shutil.rmtree(self.out, ignore_errors=True)
        self.refused("non-root")

    def test_duplicate_json_keys_are_rejected(self):
        (self.site / "policy" / "jobs.json").write_text('{"version": 2, "version": 2}')
        self.refused("duplicate JSON key")

    def test_warns_about_empty_allow_users(self):
        path = self.site / "inventory" / "group_vars" / "ubuntu_2404.yml"
        path.write_text("cis_ubuntu_2404_sshd_allow_users: []\n")
        result = self.build()
        self.assertTrue(any("sshd_allow_users" in item for item in result["warnings"]))


class CollectionTests(BuilderCase):
    def make_collections(self):
        base = self.tmp / "collections" / "ansible_collections" / "ns" / "col"
        for sub in ("plugins/modules", "tests/unit", "docs", "meta"):
            (base / sub).mkdir(parents=True)
        (base / "plugins" / "modules" / "m.py").write_text("x = 1\n")
        (base / "tests" / "unit" / "t.py").write_text("t = 1\n")
        (base / "docs" / "d.rst").write_text("doc\n")
        (base / "meta" / "runtime.yml").write_text("---\n")
        (base / "plugins" / "modules" / "__pycache__").mkdir()
        (base / "plugins" / "modules" / "__pycache__" / "m.cpython-312.pyc").write_bytes(b"\0")
        return self.tmp / "collections", base

    def test_tests_docs_and_bytecode_are_stripped(self):
        collections, _ = self.make_collections()
        result = self.build(collections=collections)
        names = self.names(result)
        prefix = "payload/collections/ansible_collections/ns/col/"
        self.assertIn(prefix + "plugins/modules/m.py", names)
        self.assertIn(prefix + "meta/runtime.yml", names)
        self.assertFalse([n for n in names if "/tests/" in n or "/docs/" in n or "__pycache__" in n])

    def test_file_links_are_dereferenced_and_dir_links_refused(self):
        collections, base = self.make_collections()
        symlink_or_skip(self, base / "meta" / "alias.yml", base / "meta" / "runtime.yml")
        result = self.build(collections=collections)
        self.assertEqual(result["symlinks"], 0)
        with tarfile.open(result["bundle"], "r:gz") as archive:
            data = archive.extractfile("payload/collections/ansible_collections/ns/col/meta/alias.yml").read()
        self.assertEqual(data, b"---\n")
        shutil.rmtree(self.out)
        symlink_or_skip(self, base / "plugins" / "dirlink", base / "meta", directory=True)
        self.refused("link is not a regular file", collections=collections)

    def test_pem_text_allowed_only_in_files_matching_upstream_checksums(self):
        collections, base = self.make_collections()
        pem = (b"-----BEGIN " + b"PRIVATE KEY-----\nexample\n-----END " + b"PRIVATE KEY-----\n")
        module = base / "plugins" / "modules" / "keystore.py"
        module.write_bytes(b'EXAMPLES = """\n' + pem + b'"""\n')
        listing = {"files": [{"name": "plugins/modules/keystore.py", "ftype": "file",
                              "chksum_type": "sha256",
                              "chksum_sha256": build.sha256_hex(module.read_bytes())}],
                   "format": 1}
        (base / "FILES.json").write_text(json.dumps(listing))
        self.build(collections=collections)
        shutil.rmtree(self.out)
        module.write_bytes(module.read_bytes() + b"# tampered\n")
        self.refused("private key material", collections=collections)

    def test_files_json_must_match_the_collection_manifest_when_present(self):
        collections, base = self.make_collections()
        pem = (b"-----BEGIN " + b"PRIVATE KEY-----\nexample\n-----END " + b"PRIVATE KEY-----\n")
        module = base / "plugins" / "modules" / "keystore.py"
        module.write_bytes(b'EXAMPLES = """\n' + pem + b'"""\n')
        listing = json.dumps({"files": [{"name": "plugins/modules/keystore.py", "ftype": "file",
                                         "chksum_type": "sha256",
                                         "chksum_sha256": build.sha256_hex(module.read_bytes())}],
                              "format": 1}).encode()
        (base / "FILES.json").write_bytes(listing)
        manifest = base / "MANIFEST.json"
        manifest.write_text(json.dumps({"file_manifest_file": {
            "name": "FILES.json", "chksum_type": "sha256", "chksum_sha256": build.sha256_hex(listing)}}))
        self.build(collections=collections)  # pinned listing is trusted
        shutil.rmtree(self.out)
        manifest.write_text(json.dumps({"file_manifest_file": {
            "name": "FILES.json", "chksum_type": "sha256", "chksum_sha256": "0" * 64}}))
        self.refused("private key material", collections=collections)

    def test_collections_need_the_expected_layout(self):
        (self.tmp / "empty").mkdir()
        self.refused("ansible_collections", collections=self.tmp / "empty")


if __name__ == "__main__":
    unittest.main()
