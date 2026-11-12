import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from unittest.mock import MagicMock


MODULE_PATH = Path(__file__).resolve().parents[1] / "local_executor.py"
SPEC = importlib.util.spec_from_file_location("local_executor", MODULE_PATH)
executor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(executor)


class LocalExecutorTests(unittest.TestCase):
    def invoke(self, host="ubuntu24", section="cron_hourly", apply=False, outcome=0):
        output = io.StringIO()
        log_file = Path("/private/record.ansible.log")
        with patch.object(executor, "host_lock", return_value=contextlib.nullcontext(42)), \
             patch.object(executor, "output_capture", return_value=contextlib.nullcontext((log_file, io.BytesIO()))), \
             patch.object(executor, "run_process", side_effect=outcome if isinstance(outcome, BaseException) else None, return_value=None if isinstance(outcome, BaseException) else (outcome, False)) as runner, \
             contextlib.redirect_stdout(output):
            code = executor.execute(host, section, apply)
        return code, [json.loads(line) for line in output.getvalue().splitlines()], runner

    def test_rejects_unknown_host_and_section_without_launch(self):
        for host, section in (("all", "cron_hourly"), ("ubuntu24,other", "cron_hourly"),
                              ("ubuntu24", "sysctl"), ("debian12", "cron_weekly"),
                              ("debian12", "cron_hourly --apply")):
            with self.subTest(host=host, section=section):
                code, events, runner = self.invoke(host, section)
                self.assertEqual(code, 2)
                self.assertEqual([item["status"] for item in events], ["rejected"])
                runner.assert_not_called()

    def test_all_four_previews_have_fixed_playbook_tag_and_gate(self):
        for host, playbook, gate in (
            ("ubuntu24", "cis_ubuntu_2404.yml", "cis_ubuntu_2404_remediation_enabled=true"),
            ("debian12", "cis_debian_12.yml", "cis_debian_12_remediation_enabled=true"),
        ):
            for section, tag in (("cron_hourly", "cis_2_4_1_3"), ("cron_daily", "cis_2_4_1_4")):
                with self.subTest(host=host, section=section):
                    code, events, runner = self.invoke(host, section)
                    self.assertEqual(code, 0)
                    self.assertEqual([item["status"] for item in events], ["accepted", "started", "completed"])
                    self.assertEqual(len({item["request_id"] for item in events}), 1)
                    self.assertEqual(events[-1]["host"], host)
                    self.assertEqual(events[-1]["section"], section)
                    self.assertEqual(events[-1]["output_file"], str(Path("/private/record.ansible.log")))
                    self.assertFalse(events[-1]["output_truncated"])
                    args = runner.call_args.args[0]
                    self.assertEqual(Path(args[1]).name, playbook)
                    self.assertEqual(args[args.index("--limit") + 1], host)
                    self.assertEqual(args[args.index("--tags") + 1], tag)
                    self.assertIn("--check", args)
                    self.assertIn("--diff", args)
                    self.assertIn(gate, args)
                    if host == "debian12":
                        self.assertIn("cis_debian_12_canary_confirmed=true", args)
                        self.assertEqual(args.count("-e"), 2)
                    else:
                        self.assertNotIn("cis_debian_12_canary_confirmed=true", args)
                        self.assertEqual(args.count("-e"), 1)
                    self.assertEqual(runner.call_args.args[1], 42)
                    self.assertEqual(executor.HOSTS[host][0].name, playbook)
                    self.assertEqual(executor.CONTROLS[section], tag)

    def test_legacy_direct_apply_is_rejected(self):
        code, events, runner = self.invoke(apply=True)
        self.assertEqual(code, 2)
        self.assertEqual([item["status"] for item in events], ["rejected"])
        runner.assert_not_called()
        with self.assertRaises(ValueError):
            executor.command("ubuntu24", "cron_hourly", True)

    def test_nonzero_exit_and_timeout_are_failures(self):
        for outcome, detail in ((3, "ansible exit code 3"), (subprocess.TimeoutExpired("ansible-playbook", 600), "timeout")):
            with self.subTest(outcome=outcome):
                code, events, _ = self.invoke(outcome=outcome)
                self.assertEqual(code, 1)
                self.assertEqual(events[-1]["status"], "failed")
                self.assertEqual(events[-1]["detail"], detail)
                self.assertEqual(events[-1]["output_file"], str(Path("/private/record.ansible.log")))

    def test_lock_conflict_does_not_launch(self):
        output = io.StringIO()
        @contextlib.contextmanager
        def busy(host):
            raise BlockingIOError("busy")
            yield
        with patch.object(executor, "host_lock", side_effect=busy), \
             patch.object(executor, "run_process") as runner, \
             contextlib.redirect_stdout(output):
            code = executor.execute("ubuntu24", "cron_hourly")
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "rejected")
        runner.assert_not_called()

    def test_child_inherits_lock_and_uses_fixed_process_environment(self):
        process = MagicMock()
        process.wait.return_value = 0
        process.stdout = io.BytesIO(b"")
        with patch.object(executor.subprocess, "Popen", return_value=process) as popen, \
             patch.object(executor.selectors, "DefaultSelector") as selector, \
             patch.object(executor, "executable_path", return_value=executor.TRUSTED_PATH) as path_resolver, \
             patch.dict(executor.os.environ, {"PATH": "/untrusted/bin", "ANSIBLE_LIBRARY": "/untrusted/modules", "SSH_AUTH_SOCK": "/untrusted/socket"}):
            selector.return_value.__enter__.return_value.get_map.return_value = {}
            self.assertEqual(executor.run_process(["ansible-playbook"], 42, io.BytesIO()), (0, False))
        options = popen.call_args.kwargs
        self.assertFalse(options["shell"])
        self.assertEqual(options["pass_fds"], (42,))
        self.assertTrue(options["start_new_session"])
        self.assertEqual(options["env"]["PATH"], executor.TRUSTED_PATH)
        path_resolver.assert_called_once_with()
        self.assertNotIn("ANSIBLE_LIBRARY", options["env"])
        self.assertNotIn("SSH_AUTH_SOCK", options["env"])

    def test_documented_lab_venv_is_selected_only_for_vagrant_checkout(self):
        fake_pwd = SimpleNamespace(getpwuid=lambda uid: SimpleNamespace(pw_name="vagrant"))
        with patch.object(executor.sys, "platform", "linux"), \
             patch.object(executor.os, "getuid", return_value=1000, create=True), \
             patch.dict(sys.modules, {"pwd": fake_pwd}), \
             patch.object(executor.Path, "home", return_value=Path("/home/vagrant")), \
             patch.object(executor, "REPO_ROOT", executor.LAB_REPO_ROOT), \
             patch.object(executor.Path, "is_file", return_value=True), \
             patch.object(executor.os, "access", return_value=True), \
             patch.dict(executor.os.environ, {"PATH": "/untrusted/bin"}):
            self.assertEqual(executor.executable_path(),
                             f"{executor.LAB_ANSIBLE_BIN}:{executor.TRUSTED_PATH}")
            with patch.object(executor.os, "getuid", return_value=0):
                self.assertEqual(executor.executable_path(), executor.TRUSTED_PATH)
            with patch.object(executor, "REPO_ROOT", Path("/elsewhere")):
                self.assertEqual(executor.executable_path(), executor.TRUSTED_PATH)

    def test_output_is_capped_without_emitting_raw_text(self):
        stream = io.BytesIO()
        with patch.object(executor, "MAX_OUTPUT_BYTES", 4):
            written, overflow = executor.write_bounded(stream, b"secret", 0)
            self.assertEqual((written, overflow), (4, True))
            written, overflow = executor.write_bounded(stream, b"more", written)
            self.assertEqual((written, overflow), (4, True))
        self.assertEqual(stream.getvalue(), b"secr")


if __name__ == "__main__":
    unittest.main()
