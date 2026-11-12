"""Synthetic local Linux release/activation tests; never invoke Ansible or SSH."""

from contextlib import contextmanager
import hashlib
import json
import os
import signal
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_managed_job import job, policy


class ManagedReleaseTests(unittest.TestCase):
    @unittest.skipUnless(Path("/usr/bin/python3").exists(), "Linux launcher required")
    def test_sealed_launcher_does_not_write_bytecode(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            module = root / "sealed_probe.py"
            module.write_text("VALUE = 1\n")
            bootstrap = root / "runtime_bootstrap.py"
            bootstrap.write_text(
                "import sys\n"
                "assert sys.flags.isolated and sys.flags.no_site\n"
                "assert sys.dont_write_bytecode\n"
                f"sys.path.insert(0, {str(root)!r})\n"
                "import sealed_probe\n"
                "assert sealed_probe.VALUE == 1\n")
            for command in ("playbook", "inventory"):
                with self.subTest(command=command):
                    launcher = root / ("ansible-" + command)
                    launcher.write_bytes(job.canonical_launcher(bootstrap, command))
                    result = subprocess.run(
                        ["/bin/sh", str(launcher)], capture_output=True, text=True,
                        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}, check=False)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertFalse((root / "__pycache__").exists())

    def stage_synthetic_release(self, release_id, bootstrap_bytes):
        release = job.RELEASES_ROOT / release_id
        payload = release / "payload"
        runtime = payload / "runtime"
        (runtime / "bin").mkdir(parents=True)
        (payload / "inventory").mkdir()
        (payload / "ansible" / "playbooks").mkdir(parents=True)
        rules = policy()
        rules.update(release_id=release_id,
                     ansible_root=str(payload / "ansible"),
                     ansible_bin_dir=str(runtime / "bin"),
                     inventory=str(payload / "inventory" / "hosts.yml"))
        raw = json.dumps(rules).encode()
        (release / "policy.json").write_bytes(raw)
        (release / "policy.json").chmod(0o600)
        (release / "release.json").write_text(json.dumps({
            "version": 1, "release_id": release_id,
            "policy_sha256": hashlib.sha256(raw).hexdigest(),
            "payload_sha256": b"tree".hex()}))
        bootstrap = runtime / "runtime_bootstrap.py"
        bootstrap.write_bytes(bootstrap_bytes)
        for command in ("playbook", "inventory"):
            (runtime / "bin" / ("ansible-" + command)).write_bytes(
                job.canonical_launcher(bootstrap, command))
        (payload / "inventory" / "hosts.yml").write_text("all: {}\n")
        (payload / "ansible" / "ansible.cfg").write_text("[defaults]\n")
        for role in ("cis_ubuntu_2404", "cis_debian_12"):
            tasks = payload / "ansible" / "roles" / role / "tasks"
            tasks.mkdir(parents=True)
            (tasks / "main.yml").write_text("---\n- name: Synthetic\n  tags: [cis_2_4_1_3]\n")
        for _, playbook, _ in job.JOBS.values():
            entry = payload / "ansible" / "playbooks" / playbook
            entry.parent.mkdir(parents=True, exist_ok=True)
            entry.write_text("---\n- hosts: all\n")
        return raw

    @contextmanager
    def deployment(self):
        # Vagrant runs tests unprivileged. Replace ownership checks only here;
        # actual Linux flock, fsync, rename and subprocess lifetime remain real.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock = root / "deployment.lock"
            lock.touch(mode=0o600)
            activated = root / "activated"
            activated.mkdir(mode=0o700)
            (root / "gateway").write_text("synthetic gateway\n")
            real_fstat = os.fstat

            def metadata(fd):
                result = real_fstat(fd)
                return SimpleNamespace(**{name: (0 if name == "st_uid" else getattr(result, name))
                                          for name in ("st_uid", "st_mode", "st_nlink", "st_size", "st_dev", "st_ino")})

            with patch.object(job, "DEPLOYMENT_LOCK", lock), \
                 patch.object(job, "POLICY_PATH", root / "jobs.json"), \
                 patch.object(job, "RELEASES_ROOT", root / "releases"), \
                 patch.object(job, "ACTIVATION_DIR", activated), \
                 patch.object(job, "ENTRYPOINT", root / "gateway"), \
                 patch.object(job, "private_directory"), \
                 patch.object(job.os, "getuid", return_value=0), \
                 patch.object(job.os, "geteuid", return_value=0), \
                 patch.object(job.os, "fstat", side_effect=metadata), \
                 patch.object(job, "trusted_file", side_effect=lambda path: path.read_bytes()):
                yield root

    def test_lock_missing_symlink_nonprivate_nonempty_and_directory_rejected(self):
        with self.deployment() as root:
            lock = job.DEPLOYMENT_LOCK
            for kind in ("missing", "symlink", "nonprivate", "nonempty", "directory", "fifo", "hardlink"):
                lock.unlink(missing_ok=True)
                if kind == "symlink":
                    lock.symlink_to(root / "other")
                elif kind == "directory":
                    lock.mkdir()
                elif kind == "fifo":
                    os.mkfifo(lock, 0o600)
                elif kind != "missing":
                    lock.touch(mode=0o644 if kind == "nonprivate" else 0o600)
                    if kind == "nonempty":
                        lock.write_text("not a stable lock")
                    if kind == "hardlink":
                        os.link(lock, root / "alias")
                with self.subTest(kind=kind), self.assertRaises((OSError, job.Reject)):
                    with job.deployment_lock():
                        self.fail("invalid lock accepted")
                if kind == "directory":
                    lock.rmdir()

    def test_service_owned_lock_rejected(self):
        with self.deployment(), patch.object(job.os, "fstat", return_value=SimpleNamespace(
                st_uid=1001, st_mode=0o100600, st_nlink=1, st_size=0)):
            with self.assertRaises(job.Reject), job.deployment_lock():
                self.fail("service-owned lock accepted")

    def test_activation_races_shared_job_and_never_reads_policy_while_busy(self):
        with self.deployment(), patch.object(job, "policy_and_hash") as read:
            with job.deployment_lock():
                with self.assertRaisesRegex(job.Reject, "deployment busy"):
                    job.activate_release("r2")
                read.assert_not_called()
            with job.deployment_lock(exclusive=True):
                with self.assertRaisesRegex(job.Reject, "deployment busy"):
                    job.run_job("ubuntu_hardening", "web01", "cron_hourly", "none")
                read.assert_not_called()

    def test_job_holds_shared_lock_until_locked_execution_returns(self):
        with self.deployment():
            def execution(*args):
                with self.assertRaisesRegex(job.Reject, "deployment busy"), job.deployment_lock(exclusive=True):
                    self.fail("deployment overlap")
                return 0
            with patch.object(job, "run_locked_job", side_effect=execution):
                self.assertEqual(job.run_job("ubuntu_audit", "web01", "none", "none"), 0)
            with job.deployment_lock(exclusive=True):
                pass

    def test_atomic_activation_one_time_id_and_crash_before_switch(self):
        with self.deployment() as root:
            def read(path=None, **_):
                path = job.POLICY_PATH if path is None else path
                return json.loads(path.read_bytes()), "fingerprint"
            for release_id in ("r1", "r2", "r3"):
                release = job.RELEASES_ROOT / release_id
                release.mkdir(parents=True)
                (release / "policy.json").write_text(json.dumps({"release_id": release_id}))
            with patch.object(job, "policy_and_hash", side_effect=read):
                job.activate_release("r1")
                self.assertEqual(read()[0]["release_id"], "r1")
                job.activate_release("r2")
                with self.assertRaises(FileExistsError):
                    job.activate_release("r1")
                with patch.object(job.os, "replace", side_effect=OSError("synthetic crash")):
                    with self.assertRaises(OSError):
                        job.activate_release("r3")
                self.assertEqual(read()[0]["release_id"], "r2")
                with self.assertRaises(FileExistsError):
                    job.activate_release("r3")
                self.assertEqual(list(root.glob(".policy-*")), [])

    def test_legacy_lab_v3_active_can_migrate_only_to_new_bootstrap(self):
        with self.deployment():
            old_bootstrap = b"synthetic legacy lab_v3 bootstrap\n"
            legacy_hash = hashlib.sha256(old_bootstrap).hexdigest()

            old_raw = self.stage_synthetic_release("lab_v3", old_bootstrap)
            new_raw = self.stage_synthetic_release("lab_v4", (Path(__file__).parents[1]
                                       / "runtime_bootstrap.py").read_bytes())
            job.POLICY_PATH.write_bytes(old_raw)
            job.POLICY_PATH.chmod(0o600)
            account = SimpleNamespace(pw_uid=1001)
            with patch.object(job, "LEGACY_LAB_V3_BOOTSTRAP_SHA256", legacy_hash), \
                 patch.object(job, "trusted_tree_digest", return_value=b"tree"), \
                 patch.object(job.pwd, "getpwnam", return_value=account), \
                 patch.object(job, "service_directory"):
                with self.assertRaisesRegex(job.Reject, "bootstrap mismatch"):
                    job.policy_and_hash()
                with self.assertRaisesRegex(job.Reject, "active policy migration"):
                    job.policy_and_hash(job.RELEASES_ROOT / "lab_v3" / "policy.json",
                                        _legacy_active=True)
                job.activate_release("lab_v4")
                self.assertEqual(job.POLICY_PATH.read_bytes(), new_raw)
                self.assertEqual(job.policy_and_hash()[0]["release_id"], "lab_v4")
                self.stage_synthetic_release("lab_v5", old_bootstrap)
                with self.assertRaisesRegex(job.Reject, "bootstrap mismatch"):
                    job.activate_release("lab_v5")
                self.assertFalse((job.ACTIVATION_DIR / "lab_v5").exists())
                with self.assertRaisesRegex(job.Reject, "new release required"):
                    job.activate_release("lab_v4")

    def test_corrupt_legacy_active_blocks_migration_without_marker(self):
        with self.deployment():
            old_bootstrap = b"synthetic legacy lab_v3 bootstrap\n"
            old_raw = self.stage_synthetic_release("lab_v3", old_bootstrap)
            self.stage_synthetic_release("lab_v4", (Path(__file__).parents[1]
                                                   / "runtime_bootstrap.py").read_bytes())
            job.POLICY_PATH.write_bytes(old_raw)
            job.POLICY_PATH.chmod(0o600)
            descriptor = job.RELEASES_ROOT / "lab_v3" / "release.json"
            descriptor.write_text(json.dumps({"version": 1, "release_id": "lab_v3",
                                              "policy_sha256": "corrupt",
                                              "payload_sha256": b"tree".hex()}))
            account = SimpleNamespace(pw_uid=1001)
            with patch.object(job, "LEGACY_LAB_V3_BOOTSTRAP_SHA256",
                              hashlib.sha256(old_bootstrap).hexdigest()), \
                 patch.object(job, "trusted_tree_digest", return_value=b"tree"), \
                 patch.object(job.pwd, "getpwnam", return_value=account), \
                 patch.object(job, "service_directory"):
                with self.assertRaisesRegex(job.Reject, "descriptor mismatch"):
                    job.activate_release("lab_v4")
            self.assertFalse((job.ACTIVATION_DIR / "lab_v4").exists())
            self.assertEqual(json.loads(job.POLICY_PATH.read_text())["release_id"], "lab_v3")

    def test_old_lab_v14_active_migrates_only_with_exact_bootstrap_and_launchers(self):
        with self.deployment():
            old_bootstrap = b"synthetic old lab_v14 bootstrap\n"
            old_hash = hashlib.sha256(old_bootstrap).hexdigest()
            old_raw = self.stage_synthetic_release("lab_v14", old_bootstrap)
            bootstrap = job.RELEASES_ROOT / "lab_v14" / "payload" / "runtime" / "runtime_bootstrap.py"
            for command in ("playbook", "inventory"):
                launcher = bootstrap.parent / "bin" / ("ansible-" + command)
                launcher.write_bytes(("#!/bin/sh\nexec /usr/bin/python3 -I -S "
                                      + str(bootstrap) + " " + command + " \"$@\"\n").encode())
            self.stage_synthetic_release("lab_v15", (Path(__file__).parents[1]
                                         / "runtime_bootstrap.py").read_bytes())
            job.POLICY_PATH.write_bytes(old_raw)
            job.POLICY_PATH.chmod(0o600)
            account = SimpleNamespace(pw_uid=1001)
            with patch.object(job, "LEGACY_LAB_V14_BOOTSTRAP_SHA256", old_hash), \
                 patch.object(job, "trusted_tree_digest", return_value=b"tree"), \
                 patch.object(job.pwd, "getpwnam", return_value=account), \
                 patch.object(job, "service_directory"):
                with self.assertRaisesRegex(job.Reject, "bootstrap mismatch"):
                    job.policy_and_hash()
                with self.assertRaisesRegex(job.Reject, "active policy migration"):
                    job.policy_and_hash(job.RELEASES_ROOT / "lab_v14" / "policy.json",
                                        _legacy_active=True)
                job.activate_release("lab_v15")
                self.assertEqual(job.policy_and_hash()[0]["release_id"], "lab_v15")

    def test_old_lab_v14_candidate_wrong_id_or_corruption_cannot_activate(self):
        with self.deployment():
            old_bootstrap = b"synthetic old lab_v14 bootstrap\n"
            old_hash = hashlib.sha256(old_bootstrap).hexdigest()

            def stage_old(release_id):
                raw = self.stage_synthetic_release(release_id, old_bootstrap)
                bootstrap = (job.RELEASES_ROOT / release_id / "payload" / "runtime"
                             / "runtime_bootstrap.py")
                for command in ("playbook", "inventory"):
                    launcher = bootstrap.parent / "bin" / ("ansible-" + command)
                    launcher.write_bytes(("#!/bin/sh\nexec /usr/bin/python3 -I -S "
                                          + str(bootstrap) + " " + command + " \"$@\"\n").encode())
                return raw, bootstrap

            old_raw, bootstrap = stage_old("lab_v14")
            wrong_raw, _ = stage_old("lab_v16")
            self.stage_synthetic_release("lab_v15", (Path(__file__).parents[1]
                                         / "runtime_bootstrap.py").read_bytes())
            account = SimpleNamespace(pw_uid=1001)
            with patch.object(job, "LEGACY_LAB_V14_BOOTSTRAP_SHA256", old_hash), \
                 patch.object(job, "trusted_tree_digest", return_value=b"tree"), \
                 patch.object(job.pwd, "getpwnam", return_value=account), \
                 patch.object(job, "service_directory"):
                with self.assertRaisesRegex(job.Reject, "bootstrap mismatch"):
                    job.activate_release("lab_v14")
                self.assertFalse((job.ACTIVATION_DIR / "lab_v14").exists())
                job.POLICY_PATH.write_bytes(old_raw)
                job.POLICY_PATH.chmod(0o600)
                with self.assertRaisesRegex(job.Reject, "bootstrap mismatch"):
                    job.activate_release("lab_v16")
                self.assertFalse((job.ACTIVATION_DIR / "lab_v16").exists())
                playbook = bootstrap.parent / "bin" / "ansible-playbook"
                original = playbook.read_bytes()
                playbook.write_bytes(original + b"# altered\n")
                with self.assertRaisesRegex(job.Reject, "launcher mismatch"):
                    job.activate_release("lab_v15")
                self.assertFalse((job.ACTIVATION_DIR / "lab_v15").exists())
                playbook.write_bytes(original)
                bootstrap.write_bytes(old_bootstrap + b"# altered\n")
                with self.assertRaisesRegex(job.Reject, "bootstrap mismatch"):
                    job.activate_release("lab_v15")
                self.assertFalse((job.ACTIVATION_DIR / "lab_v15").exists())
                bootstrap.write_bytes(old_bootstrap)
                job.POLICY_PATH.write_bytes(wrong_raw)
                with self.assertRaisesRegex(job.Reject, "bootstrap mismatch"):
                    job.activate_release("lab_v15")
                self.assertFalse((job.ACTIVATION_DIR / "lab_v15").exists())

    def test_release_descriptor_and_payload_are_bound(self):
        with self.deployment():
            rules = policy()
            release = job.RELEASES_ROOT / "r1"
            payload = release / "payload"
            release.mkdir(parents=True)
            rules.update(ansible_root=str(payload / "ansible"),
                         ansible_bin_dir=str(payload / "runtime/bin"),
                         inventory=str(payload / "inventory/hosts.yml"))
            raw = json.dumps(rules).encode()
            (release / "policy.json").write_bytes(raw)
            descriptor = {"version": 1, "release_id": "r1",
                          "policy_sha256": hashlib.sha256(raw).hexdigest(),
                          "payload_sha256": b"tree".hex()}
            (release / "release.json").write_text(json.dumps(descriptor))
            runtime = payload / "runtime"
            (runtime / "bin").mkdir(parents=True)
            bootstrap = runtime / "runtime_bootstrap.py"
            bootstrap.write_bytes((Path(__file__).parents[1] / "runtime_bootstrap.py").read_bytes())
            for command in ("playbook", "inventory"):
                (runtime / "bin" / ("ansible-" + command)).write_bytes(
                    job.canonical_launcher(bootstrap, command))
            with patch.object(job, "trusted_tree_digest", return_value=b"tree") as tree:
                first = job.release_digest(rules, raw)
                for name in ("home", "collections", "plugins", "runtime", "runtime/python"):
                    self.assertIn(payload / name, [call.args[0] for call in tree.call_args_list])
                (runtime / "bin" / "ansible-playbook").write_text("#!/bin/sh\nexit 0\n")
                with self.assertRaisesRegex(job.Reject, "launcher mismatch"):
                    job.release_digest(rules, raw)
                (runtime / "bin" / "ansible-playbook").write_bytes(
                    job.canonical_launcher(bootstrap, "playbook"))
                with self.assertRaises(job.Reject):
                    job.release_digest(rules, raw + b" ")
                with patch.object(job, "trusted_tree_digest", return_value=b"changed"):
                    with self.assertRaises(job.Reject):
                        job.release_digest(rules, raw)
                rules["ansible_root"] = "/tmp/foreign"
                with self.assertRaises(job.Reject):
                    job.release_digest(rules, raw)
                self.assertTrue(first)

    def test_invalid_release_prevents_inventory_and_ansible_launch(self):
        with self.deployment(), \
             patch.object(job, "policy_and_hash", side_effect=job.Reject("release mismatch")), \
             patch.object(job, "inventory_groups") as inventory, patch.object(job, "run_private") as run:
            with self.assertRaises(job.Reject):
                job.run_job("ubuntu_audit", "web01", "none", "none")
            inventory.assert_not_called()
            run.assert_not_called()

    def test_approval_crash_before_and_after_burn_never_launches_or_replays(self):
        approval_id = "dfca84c0-b7ef-4a9a-a1c2-76955ff426fd"
        with self.deployment() as root, patch.object(job, "APPROVAL_DIR", root), \
             patch.object(job, "run_private") as run:
            source = root / (approval_id + ".json")
            source.write_text(json.dumps({"version": 1, "job": "ubuntu_hardening", "target": "web01",
                                          "control": "cron_hourly", "change_id": "CHG123",
                                          "fingerprint": "release-policy-runtime", "expires": int(time.time()) + 60}))
            source.chmod(0o600)
            args = (approval_id, "ubuntu_hardening", "web01", "cron_hourly", "release-policy-runtime")
            with patch.object(job.os, "rename", side_effect=OSError("before burn")):
                with self.assertRaises(job.Reject):
                    job.consume_approval(*args)
            self.assertTrue(source.exists())
            with patch.object(job, "sync_directory", side_effect=OSError("after burn")):
                with self.assertRaises(job.Reject):
                    job.consume_approval(*args)
            self.assertFalse(source.exists())
            self.assertTrue((root / (approval_id + ".consumed")).exists())
            with self.assertRaises(job.Reject):
                job.consume_approval(*args)
            run.assert_not_called()

    def test_process_group_drained_after_leader_closes_output(self):
        # Child leader exits with a live same-group grandchild that closes its
        # output. The gateway must kill/drain that child before releasing flock.
        program = """
import os, time
print(os.getpgrp(), flush=True)
if os.fork() == 0:
    os.close(1); os.close(2)
    time.sleep(30)
os._exit(0)
"""
        with self.deployment() as root, patch.object(job, "drop_service"):
            output = root / "child.log"
            with job.deployment_lock():
                self.assertEqual(job.run_private([sys.executable, "-I", "-B", "-c", program],
                                                root, "unused", output, timeout=3), (-signal.SIGKILL, False))
                self.assertFalse(job.live_process_group(int(output.read_text().strip())))
            with job.deployment_lock(exclusive=True):
                pass

    def test_synthetic_activation_cli_routes_only_local_release(self):
        with patch.object(sys, "argv", ["ansible-job", "--activate", "r2"]), \
             patch.object(job, "secure_entrypoint"), patch.object(job, "activate_release") as activate:
            self.assertEqual(job.main(), 0)
            activate.assert_called_once_with("r2")

    def test_timeout_drains_process_group_before_unlock(self):
        program = "import os,time; print(os.getpgrp(),flush=True); time.sleep(30)"
        with self.deployment() as root, patch.object(job, "drop_service"):
            output = root / "timeout.log"
            with job.deployment_lock():
                with self.assertRaises(subprocess.TimeoutExpired):
                    job.run_private([sys.executable, "-I", "-B", "-c", program],
                                    root, "unused", output, timeout=0.1)
                self.assertFalse(job.live_process_group(int(output.read_text().strip())))


if __name__ == "__main__":
    unittest.main()
