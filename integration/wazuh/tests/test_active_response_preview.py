import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch


MODULE_PATH = Path(__file__).resolve().parents[1] / "active_response_preview.py"
SPEC = importlib.util.spec_from_file_location("active_response_preview", MODULE_PATH)
adapter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adapter)


def protocol(**overrides):
    message = {"version": 1, "origin": {"name": "agent", "module": "wazuh-execd"},
               "command": "add", "parameters": {"extra_args": ["ubuntu24", "cron_hourly"]}}
    message.update(overrides)
    return (json.dumps(message) + "\n").encode()


class AdapterTests(unittest.TestCase):
    def test_valid_protocol_for_exact_catalog(self):
        for host in ("ubuntu24", "debian12"):
            for section in ("cron_hourly", "cron_daily"):
                with self.subTest(host=host, section=section):
                    self.assertEqual(adapter.parse_request(protocol(
                        parameters={"extra_args": [host, section]})), (host, section))

    def test_rejects_unknown_operations_and_targets(self):
        messages = [protocol(command="delete"), protocol(parameters={"extra_args": ["all", "cron_hourly"]}),
                    protocol(parameters={"extra_args": ["ubuntu24", "cron_hourly", "--apply"]}),
                    protocol(parameters={"extra_args": ["ubuntu24", "sysctl"]}),
                    protocol(parameters={"extra_args": ["debian12", "cron_weekly"]}),
                    protocol(parameters={"extra_args": ["debian12", "cron_daily", "--apply"]}),
                    protocol(parameters={"extra_args": ["ubuntu24", "cron_hourly", "debian12"]}),
                    protocol(parameters={"extra_args": ["debian12", 1]}),
                    protocol(origin={"module": "other"}), protocol(version=2),
                    protocol(parameters={"extra_args": "ubuntu24"}), b"not json\n", b"{}\n",
                    protocol()[:-1], b"{" + b"x" * (adapter.MAX_REQUEST_BYTES + 1) + b"}\n",
                    b'{"version":1,"version":1,"origin":{"module":"wazuh-execd"},"command":"add","parameters":{"extra_args":["ubuntu24","cron_hourly"]}}\n']
        for message in messages:
            with self.subTest(message=message[:80]):
                with self.assertRaises(adapter.RejectedRequest):
                    adapter.parse_request(message)

    def test_launch_uses_fixed_preview_command_and_identity_drop(self):
        process = SimpleNamespace(stdout=__import__("io").BytesIO(b""), wait=lambda timeout=None: 0)
        with patch.object(adapter.Path, "is_file", return_value=True), \
             patch.object(adapter.os, "access", return_value=True), \
             patch.object(adapter.subprocess, "Popen", return_value=process) as popen, \
             patch.object(adapter.selectors, "DefaultSelector") as selector:
            selector.return_value.__enter__.return_value.get_map.return_value = {}
            self.assertEqual(adapter.launch_preview("debian12", "cron_daily"), (0, b"", False))
        args = popen.call_args.args[0]
        self.assertEqual(args, ["/usr/bin/python3", "-B", str(adapter.RUNNER),
                                "--host", "debian12", "--section", "cron_daily"])
        self.assertNotIn("--apply", args)
        self.assertFalse(popen.call_args.kwargs["shell"])
        self.assertIs(popen.call_args.kwargs["preexec_fn"], adapter.drop_to_vagrant)
        self.assertEqual(popen.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(popen.call_args.kwargs["stderr"], subprocess.DEVNULL)

    def test_drop_identity_order(self):
        account = SimpleNamespace(pw_name="vagrant", pw_gid=1001, pw_uid=1000)
        calls = []
        with patch.dict(sys.modules, {"pwd": SimpleNamespace(getpwnam=lambda name: account)}), \
             patch.object(adapter.os, "initgroups", side_effect=lambda *x: calls.append(("groups", x)), create=True), \
             patch.object(adapter.os, "setgid", side_effect=lambda *x: calls.append(("gid", x)), create=True), \
             patch.object(adapter.os, "setuid", side_effect=lambda *x: calls.append(("uid", x)), create=True):
            adapter.drop_to_vagrant()
        self.assertEqual([item[0] for item in calls], ["groups", "gid", "uid"])

    def test_terminal_status_requires_consistent_runner_evidence(self):
        runner_id = "a31c6775-373e-471c-a513-152306b06cc7"
        event = {"request_id": runner_id, "status": "completed", "mode": "check",
                 "host": "ubuntu24", "section": "cron_hourly"}
        output = (json.dumps(event) + "\n").encode()
        self.assertEqual(adapter.terminal_status(0, output, False, "ubuntu24", "cron_hourly"), ("completed", runner_id))
        self.assertEqual(adapter.terminal_status(1, output, False, "ubuntu24", "cron_hourly"), ("failed", runner_id))
        self.assertEqual(adapter.terminal_status(0, output, True, "ubuntu24", "cron_hourly"), ("failed", None))
        self.assertEqual(adapter.terminal_status(0, b"secret", False, "ubuntu24", "cron_hourly"), ("failed", None))
        self.assertEqual(adapter.terminal_status(0, output, False, "debian12", "cron_hourly"), ("failed", None))
        event["mode"] = "apply"
        self.assertEqual(adapter.terminal_status(0, (json.dumps(event) + "\n").encode(), False,
                                                 "ubuntu24", "cron_hourly"), ("failed", None))

    def test_identity_drop_failure_records_terminal_failure(self):
        statuses = []
        with patch.object(adapter, "secure_entrypoint"), \
             patch.object(adapter.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(protocol()))), \
             patch.object(adapter, "record", side_effect=lambda status, *args, **kwargs: statuses.append(status)), \
             patch.object(adapter, "launch_preview", side_effect=subprocess.SubprocessError("preexec failure")):
            self.assertEqual(adapter.main(), 1)
        self.assertEqual(statuses, ["accepted", "failed"])

    def test_main_passes_selected_pair_without_apply(self):
        runner_id = "a31c6775-373e-471c-a513-152306b06cc7"
        result = (json.dumps({"request_id": runner_id, "status": "completed", "mode": "check",
                              "host": "debian12", "section": "cron_daily"}) + "\n").encode()
        with patch.object(adapter, "secure_entrypoint"), \
             patch.object(adapter.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(protocol(
                 parameters={"extra_args": ["debian12", "cron_daily"]})))), \
             patch.object(adapter, "record") as record, \
             patch.object(adapter, "launch_preview", return_value=(0, result, False)) as launch:
            self.assertEqual(adapter.main(), 0)
        launch.assert_called_once_with("debian12", "cron_daily")
        self.assertEqual([call.args[0] for call in record.call_args_list], ["accepted", "completed"])
        self.assertTrue(all(call.kwargs["host"] == "debian12" and
                            call.kwargs["section"] == "cron_daily" for call in record.call_args_list))

    def test_malformed_request_uses_neutral_rejection_metadata(self):
        with patch.object(adapter, "secure_entrypoint"), \
             patch.object(adapter.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(protocol(
                 parameters={"extra_args": ["unknown", "cron_daily"]})))), \
             patch.object(adapter, "record") as record, \
             patch.object(adapter, "launch_preview") as launch:
            self.assertEqual(adapter.main(), 2)
        launch.assert_not_called()
        record.assert_called_once()
        self.assertEqual(record.call_args.args[0], "rejected")
        self.assertEqual(record.call_args.kwargs["host"], "unknown")
        self.assertEqual(record.call_args.kwargs["section"], "unknown")


if __name__ == "__main__":
    unittest.main()
