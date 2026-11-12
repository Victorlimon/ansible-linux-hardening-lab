"""The sealed Python launcher is tested without Ansible or network access."""

import os
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch


SOURCE = Path(__file__).resolve().parents[1] / "runtime_bootstrap.py"
PREPARER = SOURCE.with_name("prepare_isolated_runtime.py")


class RuntimeBootstrapTests(unittest.TestCase):
    def test_managed_helpers_are_staged_before_release_seal(self):
        spec = importlib.util.spec_from_file_location("runtime_preparer_managed", PREPARER)
        preparer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(preparer)
        with tempfile.TemporaryDirectory() as temporary:
            payload = Path(temporary) / "payload"
            payload.mkdir()
            with patch.object(preparer, "trusted_source"), \
                 patch.object(preparer, "normalize_copied_runtime"):
                preparer.stage_managed(payload)
            catalog = payload / "managed/profiles.json"
            self.assertTrue(catalog.is_file())
            self.assertIn("ubuntu_cron_hourly",
                          json.loads(catalog.read_text(encoding="utf-8"))["releases"]["lab_v10"]["section_profiles"])
            for name in preparer.MANAGED_HELPERS:
                self.assertTrue((payload / "managed/integration/wazuh" / name).is_file())

    def inventory_validation_fixture(self):
        spec = importlib.util.spec_from_file_location("runtime_preparer_inventory", PREPARER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        gateway_path = PREPARER.with_name("managed_job.py")
        gateway_spec = importlib.util.spec_from_file_location("runtime_gateway_inventory", gateway_path)
        gateway = importlib.util.module_from_spec(gateway_spec)
        with patch.dict(sys.modules, {"pwd": SimpleNamespace()}):
            gateway_spec.loader.exec_module(gateway)
        policy = {"targets": {"web01": {"host": "web01", "os": "ubuntu24"},
                              "db01": {"host": "db01", "os": "debian12"}}}
        graph = {"_meta": {"hostvars": {"web01": {"ansible_host": "192.0.2.1"},
                                         "db01": {"ansible_host": "192.0.2.2"}}},
                 "ubuntu": {"children": ["ubuntu_2404"]},
                 "ubuntu_2404": {"hosts": ["web01"]},
                 "debian_12": {"hosts": ["db01"]}}
        return module, gateway, policy, graph

    def test_preparer_inventory_requires_readable_exact_target_graph(self):
        module, gateway, policy, graph = self.inventory_validation_fixture()
        payload = Path("/opt/ansible-hardening/releases/test/payload")
        cases = [("good", graph, b"", True),
                 ("empty", {}, b"", False),
                 ("warning", graph, b"inventory unreadable\n", False),
                 ("wrong group", {**graph, "debian_12": {"hosts": []}}, b"", False),
                 ("duplicate address", {**graph, "_meta": {"hostvars": {
                     "web01": {"ansible_host": "192.0.2.1"},
                     "db01": {"ansible_host": "192.0.2.1"}}}}, b"", False)]
        for label, candidate, stderr, accepted in cases:
            with self.subTest(label=label), patch.object(module, "run_bounded",
                    return_value=(json.dumps(candidate).encode(), stderr)) as run:
                if accepted:
                    module.check_inventory(gateway, payload, "ansible-wazuh", policy)
                else:
                    with self.assertRaises(ValueError):
                        module.check_inventory(gateway, payload, "ansible-wazuh", policy)
                self.assertEqual(run.call_args.args[0], [
                    str(payload / "runtime/bin/ansible-inventory"), "-i",
                    str(payload / "inventory/hosts.yml"), "--list"])
                self.assertTrue(run.call_args.kwargs["capture_output"])
                self.assertEqual(run.call_args.kwargs["service_user"], "ansible-wazuh")
                self.assertEqual(run.call_args.kwargs["phase"], "inventory_graph")

    def test_preparer_inventory_rejects_unreadable_file_before_syntax_checks(self):
        module, gateway, policy, _ = self.inventory_validation_fixture()
        payload = Path("/opt/ansible-hardening/releases/test/payload")
        with patch.object(module, "run_bounded", side_effect=ValueError("validation failed")), \
             patch.object(module, "check_playbooks") as syntax:
            with self.assertRaisesRegex(ValueError, "validation failed"):
                module.check_inventory(gateway, payload, "ansible-wazuh", policy)
            syntax.assert_not_called()

    def run_bootstrap(self, version="2.21.2", *, poisoned=False, environment=None,
                      command="playbook", arguments=(), metadata_suffix=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            runtime.mkdir()
            bootstrap = runtime / "runtime_bootstrap.py"
            bootstrap.write_bytes(SOURCE.read_bytes())
            packages = runtime / "python"
            packages.mkdir()
            for name in ("yaml", "jinja2", "cryptography", "packaging", "resolvelib"):
                module = packages / name
                module.mkdir()
                (module / "__init__.py").write_text("", encoding="utf-8")
            ansible = packages / "ansible"
            (ansible / "cli").mkdir(parents=True)
            (ansible / "__init__.py").write_text("", encoding="utf-8")
            (ansible / "release.py").write_text(f"__version__ = {version!r}\n", encoding="utf-8")
            (ansible / "cli" / "__init__.py").write_text("", encoding="utf-8")
            external = root / "outside"
            external.mkdir()
            (external / "outside_module.py").write_text("VALUE = 1\n", encoding="utf-8")
            if metadata_suffix is not None:
                metadata = packages / ("Jinja2-3.1.2" + metadata_suffix)
                metadata.mkdir()
                (metadata / "METADATA").write_text(
                    "Metadata-Version: 2.1\nName: Jinja2\nVersion: 3.1.2\n", encoding="utf-8")
                outside_metadata = external / "outside_only_dist-9.9.dist-info"
                outside_metadata.mkdir()
                (outside_metadata / "METADATA").write_text(
                    "Metadata-Version: 2.1\nName: outside-only-dist\nVersion: 9.9\n",
                    encoding="utf-8")
            program = (f"import sys\nsys.path.insert(0, {str(external)!r})\nimport outside_module\n"
                       if poisoned else "def main():\n    return 0\n")
            if metadata_suffix is not None:
                program = ("import importlib.metadata as metadata\n"
                           f"import sys\nsys.path.insert(0, {str(external)!r})\n"
                           "def main():\n"
                           "    assert metadata.version('jinja2') == '3.1.2'\n"
                           "    try:\n"
                           "        metadata.version('outside-only-dist')\n"
                           "    except metadata.PackageNotFoundError:\n"
                           "        return 0\n"
                           "    raise AssertionError('global distribution metadata accepted')\n")
            (ansible / "cli" / "playbook.py").write_text(program, encoding="utf-8")
            env = os.environ.copy()
            env.update(environment or {})
            env["PYTHONPATH"] = str(external)
            return subprocess.run([sys.executable, "-I", "-S", str(bootstrap),
                                   command, *arguments],
                                  capture_output=True, env=env, timeout=10)

    def test_local_packages_work_without_global_site(self):
        result = self.run_bootstrap()
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_release_metadata_visible_but_global_metadata_rejected(self):
        for suffix in (".dist-info", ".egg-info"):
            with self.subTest(suffix=suffix):
                result = self.run_bootstrap(metadata_suffix=suffix)
                self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_pythonpath_cannot_supply_missing_package_or_transitive_import(self):
        result = self.run_bootstrap(poisoned=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"sealed Ansible runtime rejected", result.stderr)

    def test_exact_core_version_is_enforced(self):
        for version in ("2.15.13", "2.16.3", "2.21.1", "2.21.3", "2.21.2rc1"):
            with self.subTest(version=version):
                self.assertEqual(self.run_bootstrap(version).returncode, 2)
        self.assertEqual(self.run_bootstrap("2.21.2").returncode, 0)

    def test_preparer_requires_exact_root_source_version(self):
        spec = importlib.util.spec_from_file_location("runtime_preparer_version", PREPARER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temporary:
            release = Path(temporary) / "ansible" / "release.py"
            release.parent.mkdir()
            with patch.object(module, "trusted_source"):
                for version in ("2.16.3", "2.21.2"):
                    release.write_text(f"__version__ = {version!r}\n", encoding="utf-8")
                    self.assertEqual(module.source_core_version(release.parents[1]), version)
                    if version == "2.21.2":
                        module.require_source_core(release.parents[1])
                    else:
                        with self.assertRaisesRegex(ValueError, "2.21.2"):
                            module.require_source_core(release.parents[1])

    def test_preparer_selects_lowercase_pip_metadata_only(self):
        spec = importlib.util.spec_from_file_location("runtime_preparer_metadata", PREPARER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            names = ("ansible_core-2.21.2", "jinja2-3.1.6", "pyyaml-6.0.3",
                     "markupsafe-3.0.3", "cryptography-46.0.2", "packaging-25.0",
                     "resolvelib-1.2.1")
            expected = [source / (name + ".dist-info") for name in names]
            for item in expected:
                item.mkdir()
            (source / "unrelated-1.0.dist-info").mkdir()
            with patch.object(module, "trusted_source") as trusted:
                self.assertEqual(module.metadata_directories(source), expected)
            self.assertEqual({call.args[0] for call in trusted.call_args_list}, set(expected))

    def test_preparer_rejects_missing_and_duplicate_required_metadata(self):
        spec = importlib.util.spec_from_file_location("runtime_preparer_reject_metadata", PREPARER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            for name in module.METADATA_PACKAGES:
                (source / (name + "-1.0.dist-info")).mkdir()
            missing = source / "jinja2-1.0.dist-info"
            missing.rmdir()
            with patch.object(module, "trusted_source"):
                with self.assertRaisesRegex(ValueError, "metadata unavailable"):
                    module.metadata_directories(source)
                missing.mkdir()
                (source / "Jinja2-2.0.dist-info").mkdir()
                with self.assertRaisesRegex(ValueError, "duplicate"):
                    module.metadata_directories(source)
                (source / "Jinja2-2.0.dist-info").rmdir()
                with patch.object(module, "trusted_source", side_effect=ValueError("untrusted")):
                    with self.assertRaisesRegex(ValueError, "untrusted"):
                        module.metadata_directories(source)

    def test_preparer_syntax_checks_all_seven_catalog_playbooks(self):
        spec = importlib.util.spec_from_file_location("runtime_preparer_catalog", PREPARER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        job_ids = ("debian_preflight", "ubuntu_audit", "debian_audit",
                   "ubuntu_verify", "debian_verify", "ubuntu_hardening",
                   "debian_hardening")
        jobs = {job_id: ("ubuntu24", f"audit/{job_id}.yml", "audit")
                for job_id in job_ids}
        gateway = SimpleNamespace(JOBS=jobs, runtime_environment=lambda root: {"SEALED": str(root)})
        payload = Path("/opt/ansible-hardening/releases/test/payload")
        with patch.object(module, "run_bounded") as run:
            module.check_playbooks(gateway, payload, "ansible-wazuh")
        self.assertEqual(run.call_count, 7)
        for job_id, invocation in zip(job_ids, run.call_args_list):
            args, kwargs = invocation
            self.assertEqual(args[0][1:4], ["--syntax-check", "-i",
                                           str(payload / "inventory" / "hosts.yml")])
            self.assertEqual(args[0][4], str(payload / "ansible" / "playbooks"
                                               / f"audit/{job_id}.yml"))
            self.assertEqual(kwargs["timeout"], module.SYNTAX_CHECK_TIMEOUT)
            self.assertEqual(kwargs["environment"], {"SEALED": str(payload / "ansible")})
            self.assertEqual(kwargs["service_user"], "ansible-wazuh")
            self.assertEqual(kwargs["phase"], "syntax_" + job_id)

    def test_preparer_kills_validation_process_group_on_timeout(self):
        spec = importlib.util.spec_from_file_location("runtime_preparer_timeout", PREPARER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        process = Mock(pid=123)
        process.wait.side_effect = [subprocess.TimeoutExpired("ansible-playbook", 1), 0]
        with patch.object(module.subprocess, "Popen", return_value=process), \
             patch.object(module.os, "killpg", create=True) as kill, \
             patch.object(module.signal, "SIGKILL", 9, create=True):
            secret = "secret-value-not-for-diagnostics"
            with self.assertRaisesRegex(ValueError, "timed out.*syntax_ubuntu_audit") as caught:
                module.run_bounded(["ansible-playbook", "--syntax-check", secret],
                                   cwd=Path("/tmp"), environment={}, timeout=1,
                                   service_user="ansible-wazuh", phase="syntax_ubuntu_audit")
        self.assertNotIn("ansible-playbook", str(caught.exception))
        self.assertNotIn(secret, str(caught.exception))
        kill.assert_called_once_with(123, 9)

    def test_preparer_nonzero_reports_only_allowlisted_phase(self):
        spec = importlib.util.spec_from_file_location("runtime_preparer_failure", PREPARER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        process = Mock(pid=123)
        process.wait.return_value = 2
        secret = "secret-value-not-for-diagnostics"
        with patch.object(module.subprocess, "Popen", return_value=process):
            with self.assertRaisesRegex(ValueError, "failed.*inventory_version") as caught:
                module.run_bounded(["ansible-inventory", secret], cwd=Path("/tmp"),
                                   environment={"SECRET": secret}, timeout=1,
                                   service_user="ansible-wazuh", phase="inventory_version")
        self.assertNotIn(secret, str(caught.exception))
        self.assertNotIn("ansible-inventory", str(caught.exception))

    def test_preparer_rejects_unrecognized_phase_before_launch(self):
        spec = importlib.util.spec_from_file_location("runtime_preparer_phase", PREPARER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with patch.object(module.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(ValueError, "invalid sealed runtime validation phase"):
                module.run_bounded(["ansible-playbook"], cwd=Path("/tmp"), environment={},
                                   timeout=1, service_user="ansible-wazuh",
                                   phase="syntax_secret-value-not-for-diagnostics")
        popen.assert_not_called()

    def test_copied_runtime_permissions_normalized_from_umask_077(self):
        if os.name != "posix":
            self.skipTest("POSIX directory mode checks require Linux")
        spec = importlib.util.spec_from_file_location("runtime_preparer_modes", PREPARER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "runtime"
            nested = root / "python" / "ansible"
            nested.mkdir(parents=True)
            data = nested / "release.py"
            data.write_text("__version__ = '2.21.2'", encoding="utf-8")
            for directory in (root, root / "python", nested):
                directory.chmod(0o700)
            data.chmod(0o600)
            original_lstat = Path.lstat

            def root_owned_lstat(path):
                metadata = original_lstat(path)
                return SimpleNamespace(st_mode=metadata.st_mode, st_uid=0,
                                       st_nlink=metadata.st_nlink)

            with patch.object(module.Path, "lstat", autospec=True,
                              side_effect=root_owned_lstat):
                module.normalize_copied_runtime(root)
                self.assertEqual(
                    [p.stat().st_mode & 0o777 for p in (root, root / "python", nested)],
                    [0o755] * 3)
                self.assertEqual(data.stat().st_mode & 0o777, 0o644)
                if hasattr(os, "symlink"):
                    link = root / "python" / "link"
                    try:
                        link.symlink_to(data)
                    except (OSError, NotImplementedError):
                        pass
                    else:
                        with self.assertRaisesRegex(ValueError, "untrusted copied runtime"):
                            module.normalize_copied_runtime(root)

    def test_validation_process_drops_service_identity(self):
        spec = importlib.util.spec_from_file_location("runtime_preparer_identity", PREPARER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        process = Mock(pid=123)
        process.wait.return_value = 0
        with patch.object(module.subprocess, "Popen", return_value=process) as popen:
            module.run_bounded(["ansible-playbook", "--preflight"], cwd=Path("/tmp"),
                               environment={}, timeout=1, service_user="ansible-wazuh",
                               phase="playbook_preflight")
        self.assertIsNotNone(popen.call_args.kwargs["preexec_fn"])
        with patch.dict(sys.modules, {"pwd": SimpleNamespace(
                getpwnam=lambda name: SimpleNamespace(pw_name=name, pw_gid=2001, pw_uid=2001))}), \
             patch.object(module.os, "initgroups", create=True) as groups, \
             patch.object(module.os, "setgid", create=True) as gid, \
             patch.object(module.os, "setuid", create=True) as uid:
            popen.call_args.kwargs["preexec_fn"]()
        groups.assert_called_once_with("ansible-wazuh", 2001)
        gid.assert_called_once_with(2001)
        uid.assert_called_once_with(2001)

    def test_staging_rejects_missing_policy_scratch_and_inventory(self):
        spec = importlib.util.spec_from_file_location("runtime_preparer_prereqs", PREPARER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temporary:
            release = Path(temporary) / "lab_v6"
            payload = release / "payload"
            payload.mkdir(parents=True)
            policy_file = release / "policy.json"
            policy_file.write_text("{}", encoding="utf-8")
            policy_file.chmod(0o600)
            gateway = SimpleNamespace(LOCAL_TEMP=Path("/private/scratch"),
                                      JOBS={"one": ("ubuntu24", "audit.yml", "audit")},
                                      Reject=ValueError,
                                      unique_object=dict,
                                      trusted_file=Mock(side_effect=FileNotFoundError()),
                                      service_directory=Mock())
            with patch.dict(sys.modules, {"pwd": SimpleNamespace(
                    getpwnam=lambda name: SimpleNamespace(pw_name=name, pw_uid=2001))}), \
                 patch.object(module.Path, "stat", return_value=SimpleNamespace(st_mode=0o100600)):
                with self.assertRaisesRegex(ValueError, "staging policy"):
                    module.staging_service(gateway, release, payload)
                policy = {"version": 2, "release_id": "lab_v6",
                          "ansible_root": str(payload / "ansible"),
                          "ansible_bin_dir": str(payload / "runtime" / "bin"),
                          "inventory": str(payload / "inventory" / "hosts.yml"),
                          "service_user": "ansible-wazuh"}
                gateway.trusted_file.side_effect = None
                gateway.trusted_file.return_value = __import__("json").dumps(policy).encode()
                with patch.dict(sys.modules, {"pwd": SimpleNamespace(
                        getpwnam=Mock(side_effect=KeyError("account missing")))}):
                    with self.assertRaisesRegex(ValueError, "service account"):
                        module.staging_service(gateway, release, payload)
                gateway.service_directory.side_effect = ValueError("scratch missing")
                with self.assertRaisesRegex(ValueError, "scratch"):
                    module.staging_service(gateway, release, payload)
                gateway.service_directory.side_effect = None
                gateway.trusted_file.side_effect = [__import__("json").dumps(policy).encode(),
                                                    FileNotFoundError("inventory missing")]
                with self.assertRaisesRegex(ValueError, "inventory"):
                    module.staging_service(gateway, release, payload)

    def test_preflight_does_not_run_ansible_cli(self):
        result = self.run_bootstrap(poisoned=True, arguments=("--preflight",))
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_unknown_command_is_rejected(self):
        result = self.run_bootstrap(command="adhoc")
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"invalid sealed Ansible command", result.stderr)

    def test_preparer_import_does_not_import_gateway(self):
        # managed_job imports Linux-only pwd. Loading the preparer itself must
        # not load that gateway before trusted-source checks can run.
        spec = importlib.util.spec_from_file_location("runtime_preparer_test", PREPARER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertTrue(callable(module.load_gateway))

    def test_runtime_requires_isolated_no_site_flags(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary) / "runtime"
            runtime.mkdir()
            bootstrap = runtime / "runtime_bootstrap.py"
            bootstrap.write_bytes(SOURCE.read_bytes())
            (runtime / "python").mkdir()
            result = subprocess.run([sys.executable, str(bootstrap), "playbook", "--preflight"],
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertIn(b"isolated Python", result.stderr)

    def test_later_sys_path_insert_cannot_import_nested_global_sites(self):
        spec = importlib.util.spec_from_file_location("sealed_bootstrap_test", SOURCE)
        bootstrap = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(bootstrap)
        with tempfile.TemporaryDirectory() as temporary:
            standard = Path(temporary) / "stdlib"
            standard.mkdir()
            finder = bootstrap.SealedPathFinder((standard,), standard)
            original_path = sys.path[:]
            try:
                for site_name in ("site-packages", "dist-packages"):
                    with self.subTest(site_name=site_name):
                        site = standard / "vendor" / site_name
                        site.mkdir(parents=True)
                        (site / "untrusted_test_module.py").write_text("VALUE = 1\n", encoding="utf-8")
                        (site / "untrusted_test_package").mkdir()
                        sys.path.insert(0, str(site))
                        with self.assertRaisesRegex(ImportError, "outside sealed Python runtime"):
                            finder.find_spec("untrusted_test_module")
                        with self.assertRaisesRegex(ImportError, "outside sealed Python runtime"):
                            finder.find_spec("untrusted_test_package")
                        sys.path.pop(0)
            finally:
                sys.path[:] = original_path


if __name__ == "__main__":
    unittest.main()
