import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from contextlib import nullcontext


MODULE_PATH = Path(__file__).resolve().parents[1] / "managed_job.py"
SPEC = importlib.util.spec_from_file_location("managed_job", MODULE_PATH)
job = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(job)


def protocol(args):
    return (json.dumps({"version": 1, "origin": {"module": "wazuh-execd"},
                        "command": "add", "parameters": {"extra_args": args}}) + "\n").encode()


def managed_args(kind="managed-check-v1"):
    args = [kind, "1fca84c0-b7ef-4a9a-a1c2-76955ff426fd", "lab_v10",
            "ubuntu_lab", "ubuntu24", "ssh_baseline", "ubuntu24", "CHG123"]
    if kind == "managed-apply-v1":
        args.append("dfca84c0-b7ef-4a9a-a1c2-76955ff426fd")
    return args


def v2_order(**updates):
    data = {"mode": "check", "request_id": managed_args()[1], "change_id": "CHG123",
            "release_id": "r1", "playbook_id": "ubuntu_hardening",
            "inventory_profile_id": "ubuntu_lab", "targets": ["web01"],
            "selection": {"kind": "full", "names": []}, "extra_vars": {}}
    data.update(updates)
    return ["managed-v2", json.dumps(data, sort_keys=True, separators=(",", ":"))]


def policy():
    return {"version": 2, "release_id": "r1",
            "ansible_root": "/opt/ansible-hardening/releases/r1/payload/ansible",
            "ansible_bin_dir": "/opt/ansible-hardening/releases/r1/payload/runtime/bin",
            "inventory": "/opt/ansible-hardening/releases/r1/payload/inventory/hosts.yml",
            "service_user": "ansible-wazuh",
            "targets": {"web01": {"host": "web01", "os": "ubuntu24"},
                        "db01": {"host": "db01", "os": "debian12"}},
            "controls": {"cron_hourly": {"tag": "cis_2_4_1_3", "os": ["ubuntu24", "debian12"]}}}


class ManagedJobTests(unittest.TestCase):
    def test_sealed_gateway_disables_bytecode_writes(self):
        self.assertTrue(job.sys.dont_write_bytecode)

    def test_v2_full_order_and_legacy_do_not_confuse_authority(self):
        request = job.parse_wazuh(protocol(v2_order()))
        self.assertIs(type(request), job.ManagedV2Request)
        self.assertEqual(request.kind, job.RequestKind.MANAGED_V2)
        self.assertEqual(request.mode, "check")
        with patch.object(job, "run_managed_v2", return_value=0) as run:
            self.assertEqual(job.dispatch_request(request), 0)
            run.assert_called_once_with(request)
        self.assertEqual(job.parse_wazuh(protocol(managed_args("managed-apply-v1"))).kind,
                         job.RequestKind.MANAGED_APPLY)

    def test_v2_rejection_retains_request_correlation(self):
        frame = protocol(v2_order())
        with patch.object(sys, "argv", ["ansible-job"]), \
             patch.object(sys, "stdin", io.TextIOWrapper(io.BytesIO(frame))), \
             patch.object(job, "secure_entrypoint"), \
             patch.object(job, "run_managed_v2", side_effect=job.Reject("no task")), \
             patch.object(job, "emit") as emit:
            self.assertEqual(job.main(), 2)
            emit.assert_called_once_with("rejected", managed_args()[1],
                                         "ubuntu_hardening", "batch", "full", "check",
                                         change_id="CHG123")

    def test_v2_rejects_extra_duplicate_and_oversized_json(self):
        for payload in (v2_order(path="/tmp/playbook"),
                        ["managed-v2", '{"mode":"check","mode":"apply"}'],
                        ["managed-v2", "x" * 8193]):
            with self.subTest(payload=payload[1][:40]), self.assertRaises(job.Reject):
                job.parse_wazuh(protocol(payload))

    def test_v2_rejects_apply_without_exact_approval_map(self):
        for approvals in ({}, {"other": managed_args()[1]},
                          {"web01": "bad-uuid"}):
            request = job.parse_wazuh(protocol(v2_order(mode="apply", approvals=approvals))) if approvals != {"web01": "bad-uuid"} else None
            if request is not None:
                with patch.object(job, "load_managed_catalog", return_value={"releases": {"r1": {"inventory_profiles": {"ubuntu_lab": {"platform": "ubuntu24", "aliases": ["web01"]}}}}}), \
                     patch.object(job, "trusted_file", return_value=b"- name: Remediate Ubuntu CIS 4.2.6\n  tags: [cis_4_2_6]\n"):
                    with self.assertRaises(job.Reject):
                        job._v2_plan(policy(), "a" * 64, request,
                                     {"ubuntu": {"hosts": ["web01"]}})
            else:
                with self.assertRaises(job.Reject):
                    job.parse_wazuh(protocol(v2_order(mode="apply", approvals=approvals)))

    def test_v2_group_with_unapproved_host_fails_before_launch(self):
        request = job.parse_wazuh(protocol(v2_order(targets=["production_group"])))
        inventory = {"production_group": {"hosts": ["web01", "unapproved"]},
                     "ubuntu": {"hosts": ["web01", "unapproved"]}}
        catalog = {"releases": {"r1": {"inventory_profiles": {
            "ubuntu_lab": {"platform": "ubuntu24", "aliases": ["web01"]}}}}}
        with patch.object(job, "load_managed_catalog", return_value=catalog), \
             patch.object(job, "trusted_file", return_value=b"- name: Remediate Ubuntu CIS 4.2.6\n  tags: [cis_4_2_6]\n"):
            with self.assertRaises(job.Reject):
                job._v2_plan(policy(), "a" * 64, request, inventory)

    def test_v2_rejects_inert_tag_and_accepts_existing_remediation_tag(self):
        inventory = {"ubuntu": {"hosts": ["web01"]}}
        catalog = {"releases": {"r1": {"inventory_profiles": {
            "ubuntu_lab": {"platform": "ubuntu24", "aliases": ["web01"]}}}}}
        role = b"- name: Remediate Ubuntu 24.04 CIS 4.2.6\n  tags: [cis_4_2_6]\n"
        with patch.object(job, "load_managed_catalog", return_value=catalog), \
             patch.object(job, "trusted_file", return_value=role):
            valid = job.parse_wazuh(protocol(v2_order(selection={"kind": "tags", "names": ["cis_4_2_6"]})))
            hosts, plan = job._v2_plan(policy(), "a" * 64, valid, inventory)
            self.assertEqual(hosts, ("web01",))
            self.assertEqual(plan["tags"], ["cis_4_2_6"])
            inert = job.parse_wazuh(protocol(v2_order(selection={"kind": "tags", "names": ["cis_4_2_7"]})))
            with self.assertRaises(job.Reject):
                job._v2_plan(policy(), "a" * 64, inert, inventory)

    def test_v2_rejects_unsafe_or_inert_firewall_vars(self):
        invalid = [
            {"cis_ufw_ssh_port": 0},
            {"cis_ufw_ssh_allowed_sources": ["0.0.0.0/0"]},
            {"cis_nftables_config": "table inet filter {}"},
            {"cis_ufw_allowed_in_rules": [{"from_ip": "any", "port": 22, "proto": "tcp"}]},
            {"cis_ufw_allowed_in_rules": [{"from_ip": "any", "port": 443, "proto": "tcp"}]},
            {"cis_ufw_allowed_in_rules": [{"from_ip": "any", "port": 443, "proto": "tcp", "shell": "x"}]},
        ]
        for variables in invalid:
            with self.subTest(variables=variables), self.assertRaises(job.Reject):
                job.parse_wazuh(protocol(v2_order(extra_vars=variables)))
        good = {"cis_ufw_ssh_port": 2222,
                "cis_ufw_ssh_allowed_sources": ["10.20.30.0/24"],
                "cis_ufw_allowed_in_rules": [{"from_ip": "10.20.30.0/24", "port": 443, "proto": "tcp"}]}
        self.assertEqual(job.parse_wazuh(protocol(v2_order(extra_vars=good))).extra_vars, good)

    def test_v2_full_argv_is_fixed_and_mode_specific(self):
        request = job.parse_wazuh(protocol(v2_order()))
        plan = {"tags": ["cis_ubuntu_2404_remediation"]}
        check = job._v2_args(policy(), request, "web01", plan, None)
        self.assertEqual(check[-2:], ["--check", "--diff"])
        self.assertEqual(check[check.index("--limit") + 1], "web01")
        self.assertEqual(check[check.index("--tags") + 1], "cis_ubuntu_2404_remediation")
        apply = job._v2_args(policy(), request._replace(mode="apply"), "web01", plan, None)
        self.assertNotIn("--check", apply)

    def test_v2_read_only_check_runs_audit_and_verify_commands(self):
        for playbook_id in ("ubuntu_audit", "debian_audit", "ubuntu_verify", "debian_verify"):
            with self.subTest(playbook_id=playbook_id):
                request = job.parse_wazuh(protocol(v2_order(playbook_id=playbook_id)))
                args = job._v2_args(policy(), request, "web01", {"tags": ["cis_3_3_10"]}, None)
                self.assertNotIn("--check", args)
                self.assertNotIn("--diff", args)
                self.assertEqual(args[args.index("--tags") + 1], "cis_3_3_10")

    def test_v2_check_approval_apply_single_host_creates_durable_terminal(self):
        request = job.parse_wazuh(protocol(v2_order()))
        inventory = {"ubuntu": {"hosts": ["web01"]}}
        catalog = {"releases": {"r1": {"inventory_profiles": {
            "ubuntu_lab": {"platform": "ubuntu24", "aliases": ["web01"]}}}}}
        recap = b"PLAY RECAP ****************\nweb01 : ok=2 changed=1 unreachable=0 failed=0 skipped=0\n"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, approvals = root / "state", root / "approvals"
            state.mkdir()
            approvals.mkdir()
            commands = []
            def fake_run(args, cwd, service, output, **kwargs):
                if "--list-tasks" in args:
                    output.write_bytes(b"play #1\n  tasks:\n    cis_ubuntu_2404 : Remediate safe task  TAGS: [cis_ubuntu_2404_remediation]\n")
                    return 0, False
                commands.append(args)
                output.write_bytes(recap)
                return 0, False
            def read(path, **kwargs):
                if path.name == "main.yml":
                    return b"- name: Remediate Ubuntu CIS 4.2.6\n  tags: [cis_4_2_6]\n"
                return path.read_bytes()
            with patch.object(job, "STATE_DIR", state), \
                 patch.object(job, "APPROVAL_DIR", approvals), \
                 patch.object(job, "deployment_lock", return_value=nullcontext()), \
                 patch.object(job, "private_directory"), \
                 patch.object(job, "policy_and_hash", return_value=(policy(), "a" * 64)), \
                 patch.object(job, "load_managed_catalog", return_value=catalog), \
                 patch.object(job, "inventory_groups", return_value=inventory), \
                 patch.object(job, "unique_target_addresses"), \
                 patch.object(job, "trusted_file", side_effect=read), \
                 patch.object(job, "run_private", side_effect=fake_run), \
                 patch.object(job, "_v2_event"):
                self.assertEqual(job.run_managed_v2(request), 0)
                with self.assertRaises(job.Reject):
                    job.issue_managed_v2_approval(request.request_id, "web01", "reviewer", "OOB checked")
                with self.assertRaises(job.Reject):
                    job.issue_managed_v2_approval(request.request_id, "web01", "reviewer", "OOB checked",
                                                  backup_ref="BACKUP123", oob_ref="CONSOLE123",
                                                  change_ref="CHG123")
                check_record = json.loads(job._v2_path(request.request_id, "web01", "check.json").read_text())
                job._v2_path(request.request_id, "web01", "safety.json").write_text(json.dumps({
                    "version": 1, "request_id": request.request_id, "change_id": "CHG123",
                    "host": "web01", "scope_digest": check_record["plan"]["scope_digest"],
                    "backup_ref": "BACKUP123", "oob_ref": "CONSOLE123",
                    "expires_at": int(time.time()) + 600}), encoding="ascii")
                approval = job.issue_managed_v2_approval(request.request_id, "web01", "reviewer", "OOB checked",
                                                          backup_ref="BACKUP123", oob_ref="CONSOLE123",
                                                          change_ref="CHG123")
                apply = request._replace(mode="apply", approvals={"web01": approval})
                safety_path = job._v2_path(request.request_id, "web01", "safety.json")
                original_safety = safety_path.read_bytes()
                safety_path.write_bytes(original_safety.replace(b"BACKUP123", b"OTHER123"))
                with self.assertRaises(job.Reject):
                    job.run_managed_v2(apply)
                safety_path.write_bytes(original_safety)
                self.assertEqual(job.run_managed_v2(apply), 0)
                self.assertEqual(len(commands), 2)
                with self.assertRaises(job.Reject):
                    job.run_managed_v2(apply._replace(approvals={"web01": managed_args()[1]}))
                self.assertEqual(commands[0][-2:], ["--check", "--diff"])
                self.assertNotIn("--check", commands[1])
                self.assertFalse((state / "web01.managed-v2.active").exists())
                self.assertTrue(job._v2_path(request.request_id, "web01", "terminal.json").exists())
                self.assertEqual(job.run_managed_v2(apply), 0)
                self.assertEqual(len(commands), 2)

    def test_v2_selection_requires_effective_ansible_task_listing(self):
        request = job.parse_wazuh(protocol(v2_order(selection={"kind": "tags", "names": ["cis_4_2_6"]})))
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(job, "STATE_DIR", Path(temporary)), \
                 patch.object(job, "trusted_file", side_effect=lambda path: path.read_bytes()), \
                 patch.object(job, "run_private", side_effect=lambda args, cwd, service, output, **kw:
                              (output.write_bytes(b"play #1\n  tasks:\n    cis_platform_preflight : Check\tTAGS: [always]\n"), 0, False)[1:]):
                with self.assertRaises(job.Reject):
                    job._v2_selected_tasks(policy(), request, "web01", {"tags": ["cis_4_2_6"]}, None)
                self.assertEqual(list(Path(temporary).glob("*.selected-tasks.log")), [])

    def test_v2_successful_task_listing_removes_private_output(self):
        request = job.parse_wazuh(protocol(v2_order(selection={"kind": "tags", "names": ["cis_4_2_6"]})))
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(job, "STATE_DIR", Path(temporary)), \
                 patch.object(job, "trusted_file", side_effect=lambda path: path.read_bytes()), \
                 patch.object(job, "run_private", side_effect=lambda args, cwd, service, output, **kw:
                              (output.write_bytes(b"play #1\n  tasks:\n    cis_4_2_6 : Remediate\tTAGS: [cis_4_2_6]\n"), 0, False)[1:]):
                digest = job._v2_selected_tasks(policy(), request, "web01", {"tags": ["cis_4_2_6"]}, None)
                self.assertEqual(len(digest), 64)
                self.assertEqual(list(Path(temporary).glob("*.selected-tasks.log")), [])

    def test_v2_terminal_event_recovery_keeps_blocker_until_published(self):
        request = job.parse_wazuh(protocol(v2_order(mode="apply", approvals={"web01": managed_args()[1]})))
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            plan = {"scope_digest": "a" * 64}
            terminal = {"version": 2, "host": "web01", "plan": plan,
                        "approval_id": managed_args()[1], "status": "completed"}
            path = state / (request.request_id + ".web01.v2.terminal.json")
            path.write_text(json.dumps(terminal), encoding="ascii")
            blocker = state / "web01.managed-v2.active"
            blocker.write_text(json.dumps({"request_id": request.request_id,
                                           "scope_digest": plan["scope_digest"]}), encoding="ascii")
            with patch.object(job, "STATE_DIR", state), \
                 patch.object(job, "trusted_file", side_effect=lambda path: path.read_bytes()), \
                 patch.object(job, "_v2_event", side_effect=[OSError("log unavailable"), None]) as event:
                with self.assertRaises(OSError):
                    job._v2_publish_terminal(request, "web01", plan, terminal, path)
                self.assertTrue(blocker.exists())
                job._v2_publish_terminal(request, "web01", plan, terminal, path)
                self.assertFalse(blocker.exists())
                self.assertTrue(job._v2_path(request.request_id, "web01", "terminal-published.json").exists())
                self.assertEqual(event.call_count, 2)

    def test_manual_approval_uses_only_completed_root_evidence(self):
        request_id = managed_args()[1]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            diff = b"approved diff"
            (root / (request_id + ".managed-check.log")).write_bytes(diff)
            evidence = {"version": 1, "request_id": request_id,
                        "release_id": "r1", "release_digest": "a" * 64,
                        "profile_digest": "b" * 64, "diff_digest": job.hashlib.sha256(diff).hexdigest(),
                        "inventory_profile_id": "inventory_lab", "host_profile_id": "ubuntu_lab",
                        "section_profile_id": "cron_hourly", "target_alias": "web01",
                        "section": "cron_hourly", "change_id": "CHG123"}
            (root / (request_id + ".check.json")).write_text(json.dumps(evidence), encoding="utf-8")
            supervisor = SimpleNamespace(create_approval=Mock(return_value=SimpleNamespace(approval_id="approved")),
                                         issue=Mock())
            with patch.object(job, "STATE_DIR", root), \
                 patch.object(job, "deployment_lock", return_value=nullcontext()), \
                 patch.object(job, "private_directory"), \
                 patch.object(job, "policy_and_hash", return_value=(policy(), "a" * 64)), \
                 patch.object(job, "trusted_file", side_effect=lambda path: path.read_bytes()), \
                 patch.object(job, "load_managed_supervisor", return_value=supervisor):
                self.assertEqual(job.issue_managed_approval(request_id, "reviewer", "reviewed", 300), "approved")
                supplied = supervisor.create_approval.call_args.kwargs
                self.assertEqual(supplied["request_id"], request_id)
                self.assertEqual(supplied["diff_digest"], evidence["diff_digest"])
                self.assertEqual(supplied["target_alias"], "web01")
                supervisor.issue.assert_called_once()
                (root / (request_id + ".managed-check.log")).write_bytes(b"changed")
                with self.assertRaises(job.Reject):
                    job.issue_managed_approval(request_id, "reviewer", "reviewed", 300)
                self.assertEqual(supervisor.issue.call_count, 1)

    def test_managed_check_creates_immutable_root_evidence(self):
        request = job.ManagedCheckRequest(
            managed_args()[1], "r1", "inventory_lab", "ubuntu_lab",
            "cron_hourly", "web01", "CHG123")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / (request.request_id + ".managed-check.log")
            evidence = root / (request.request_id + ".check.json")
            def run(args, cwd, service, output_path, **kwargs):
                self.assertIn("--check", args)
                self.assertIn("--diff", args)
                self.assertNotIn("--extra-vars", args)
                output_path.write_bytes(b"reviewed diff")
                return 0, False
            with patch.object(job, "STATE_DIR", root), \
                 patch.object(job, "deployment_lock", return_value=nullcontext()), \
                 patch.object(job, "private_directory"), \
                 patch.object(job, "policy_and_hash", return_value=(policy(), "a" * 64)), \
                 patch.object(job, "run_private", side_effect=run), \
                 patch.object(job, "inventory_groups", return_value={"_meta": {"hostvars": {}}, "ubuntu": {"hosts": ["web01"]}}), \
                 patch.object(job, "unique_target_addresses"), \
                 patch.object(job, "load_managed_catalog", return_value={"releases": {"r1": {}}}), \
                 patch.object(job, "resolve_managed_profile") as resolve, \
                 patch.object(job, "emit"), \
                 patch.object(job, "trusted_file", side_effect=lambda path: path.read_bytes()):
                resolve.return_value = SimpleNamespace(
                    release_id="r1", inventory_profile_id="inventory_lab",
                    host_profile_id="ubuntu_lab", section_profile_id="cron_hourly",
                    target_alias="web01", platform="ubuntu24", section="cron_hourly",
                    tags=("cis_2_4_1_3",),
                    gates=("cis_ubuntu_2404_remediation_enabled",),
                    disposition="automated", network_rules=(), digest="b" * 64)
                self.assertEqual(job.run_managed_check(request), 0)
                record = json.loads(evidence.read_text(encoding="utf-8"))
                self.assertEqual(record["request_id"], request.request_id)
                self.assertEqual(record["change_id"], request.change_id)
                self.assertEqual(record["diff_digest"], job.hashlib.sha256(b"reviewed diff").hexdigest())
                with self.assertRaises(job.Reject):
                    job.run_managed_check(request._replace(change_id="OTHER"))

    def test_legacy_request_is_typed_immutable_and_always_check(self):
        for slot in ("none", managed_args()[1]):
            with self.subTest(slot=slot):
                request = job.parse_wazuh(protocol(
                    ["ubuntu_hardening", "web01", "cron_hourly", slot]))
                self.assertIsInstance(request, job.LegacyCheckRequest)
                self.assertEqual(request.kind, job.RequestKind.LEGACY_CHECK)
                self.assertEqual(request.approval_slot, slot)
                with self.assertRaises(AttributeError):
                    request.approval_slot = "none"

    def test_legacy_uuid_dispatch_cannot_request_apply_or_consume_approval(self):
        frame = protocol(["ubuntu_hardening", "web01", "cron_hourly", managed_args()[1]])
        with patch.object(sys, "argv", ["ansible-job"]), \
             patch.object(sys, "stdin", io.TextIOWrapper(io.BytesIO(frame))), \
             patch.object(job, "secure_entrypoint"), \
             patch.object(job, "consume_approval") as consume, \
             patch.object(job, "run_job", return_value=0) as run:
            self.assertEqual(job.main(), 0)
            run.assert_called_once_with("ubuntu_hardening", "web01", "cron_hourly", "none")
            consume.assert_not_called()

    def test_managed_contracts_have_exact_typed_immutable_fields(self):
        for kind in ("managed-check-v1", "managed-apply-v1"):
            with self.subTest(kind=kind):
                args = managed_args(kind)
                request = job.parse_wazuh(protocol(args))
                expected = (job.ManagedCheckRequest if len(args) == 8
                            else job.ManagedApplyRequest)
                self.assertIs(type(request), expected)
                self.assertEqual(request.kind.value, kind)
                self.assertEqual(tuple(request), tuple(args[1:]))
                self.assertEqual(request.request_id, args[1])
                self.assertEqual(request.release_id, args[2])
                self.assertEqual(request.inventory_profile_id, args[3])
                self.assertEqual(request.host_profile_id, args[4])
                self.assertEqual(request.section_profile_id, args[5])
                self.assertEqual(request.target_alias, args[6])
                self.assertEqual(request.change_id, args[7])
                self.assertFalse(hasattr(request, "release_digest"))
                self.assertFalse(hasattr(request, "profile_digest"))
                with self.assertRaises(AttributeError):
                    request.target_alias = "other"

    def test_managed_contract_rejects_missing_extra_or_nonstring_arguments(self):
        for kind in ("managed-check-v1", "managed-apply-v1"):
            valid = managed_args(kind)
            cases = [valid[:length] for length in range(len(valid))]
            cases += [valid + ["extra"], {"args": valid}, " ".join(valid)]
            for index in range(len(valid)):
                for value in (None, True, 1, [], {}):
                    args = valid.copy()
                    args[index] = value
                    cases.append(args)
            for args in cases:
                with self.subTest(kind=kind, args=args), self.assertRaises(job.Reject):
                    job.parse_wazuh(protocol(args))

    def test_managed_contract_rejects_hostile_fields_before_dispatch(self):
        hostile = ("/tmp/playbook.yml", "../README.md", "C:\\temp\\payload.yml",
                   "--extra-vars", "-e", "key=value", "HOME=/tmp", "$(id)",
                   "x;id", "x|id", "x&id", "x`id`", "a b", "a\nb", "a\x00b",
                   "sha256:" + "a" * 64, "a" * 64, "éxample", "a" * 65)
        for kind in ("managed-check-v1", "managed-apply-v1"):
            for index in range(1, len(managed_args(kind))):
                for value in hostile:
                    args = managed_args(kind)
                    args[index] = value
                    with self.subTest(kind=kind, index=index, value=value), \
                         patch.object(job, "run_job") as legacy, \
                         patch.object(job, "policy_and_hash") as policy_read, \
                         patch.object(job.os, "open") as opened, \
                         patch.object(job.subprocess, "Popen") as spawned:
                        with self.assertRaises(job.Reject):
                            job.parse_wazuh(protocol(args))
                        legacy.assert_not_called()
                        policy_read.assert_not_called()
                        opened.assert_not_called()
                        spawned.assert_not_called()

    def test_managed_uuid_and_target_canonicality(self):
        canonical = managed_args()[1]
        invalid = (canonical.upper(), canonical.replace("-", ""), "{" + canonical + "}",
                   "urn:uuid:" + canonical, "00000000-0000-0000-0000-000000000000", "none")
        for kind in ("managed-check-v1", "managed-apply-v1"):
            for index in ((1,) if kind == "managed-check-v1" else (1, 8)):
                for value in invalid:
                    args = managed_args(kind)
                    args[index] = value
                    with self.subTest(kind=kind, index=index, value=value), self.assertRaises(job.Reject):
                        job.parse_wazuh(protocol(args))
            for target in ("all", "ungrouped", "web01,db01", "web*"):
                args = managed_args(kind)
                args[6] = target
                with self.subTest(target=target), self.assertRaises(job.Reject):
                    job.parse_wazuh(protocol(args))

    def test_managed_dispatch_uses_only_typed_paths(self):
        with patch.object(job, "run_job") as legacy, \
             patch.object(job, "run_managed_check", return_value=0) as check, \
             patch.object(job, "consume_approval") as consume:
            request = job.parse_wazuh(protocol(managed_args("managed-check-v1")))
            self.assertEqual(job.dispatch_request(request), 0)
            check.assert_called_once_with(request)
            apply_request = job.parse_wazuh(protocol(managed_args("managed-apply-v1")))
            with self.assertRaisesRegex(job.Reject, "managed apply disabled"):
                job.dispatch_request(apply_request)
            legacy.assert_not_called()
            consume.assert_not_called()

    def test_managed_main_rejects_without_falling_back_to_legacy(self):
        for kind in ("managed-check-v1", "managed-apply-v1"):
            with self.subTest(kind=kind), \
                 patch.object(sys, "argv", ["ansible-job"]), \
                 patch.object(sys, "stdin", io.TextIOWrapper(io.BytesIO(protocol(managed_args(kind))))), \
                 patch.object(job, "secure_entrypoint"), patch.object(job, "emit"), \
                 patch.object(job, "run_job") as legacy, \
                 patch.object(job, "run_managed_check", return_value=0) as check, \
                 patch.object(job, "run_private") as run, \
                 patch.object(job, "consume_approval") as consume:
                self.assertEqual(job.main(), 0 if kind == "managed-check-v1" else 2)
                legacy.assert_not_called()
                run.assert_not_called()
                consume.assert_not_called()
                self.assertEqual(check.call_count, 1 if kind == "managed-check-v1" else 0)

    def test_no_argv_main_reads_actual_wazuh_frame(self):
        frame = protocol(["ubuntu_hardening", "web01", "cron_hourly", "none"])
        with patch.object(sys, "argv", ["ansible-job"]), \
             patch.object(sys, "stdin", io.TextIOWrapper(io.BytesIO(frame))), \
             patch.object(job, "secure_entrypoint") as installed, \
             patch.object(job, "run_job", return_value=0) as run:
            self.assertEqual(job.main(), 0)
            installed.assert_called_once()
            run.assert_called_once_with("ubuntu_hardening", "web01", "cron_hourly", "none")

    def test_no_argv_cli_synthetic_api_frame(self):
        # Execute real main in a separate interpreter. Only installation and
        # launch boundaries are replaced; no Ansible or remote operation runs.
        harness = """
import importlib.util, sys
spec = importlib.util.spec_from_file_location('managed_job', sys.argv[1])
job = importlib.util.module_from_spec(spec)
spec.loader.exec_module(job)
job.secure_entrypoint = lambda: None
job.run_job = lambda *args: 0 if args == ('ubuntu_hardening', 'web01', 'cron_hourly', 'none') else 9
sys.argv = ['ansible-job']
sys.exit(job.main())
"""
        result = subprocess.run([sys.executable, "-I", "-B", "-c", harness, str(MODULE_PATH)],
                                input=protocol(["ubuntu_hardening", "web01", "cron_hourly", "none"]),
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout, b"")

    def test_no_argv_rejection_never_echoes_untrusted_input(self):
        with patch.object(sys, "argv", ["ansible-job"]), \
             patch.object(sys, "stdin", io.TextIOWrapper(io.BytesIO(b'{"secret":"private"}\n'))), \
             patch.object(sys, "stdout", io.StringIO()) as output, \
             patch.object(job, "secure_entrypoint"), patch.object(job, "emit") as event, \
             patch.object(job, "run_job") as run:
            self.assertEqual(job.main(), 2)
            self.assertEqual(output.getvalue(), "")
            self.assertNotIn("private", repr(event.call_args))
            self.assertEqual(event.call_args.args[0], "rejected")
            run.assert_not_called()

    def test_service_home_and_loader_paths_are_not_service_writable(self):
        root = Path(policy()["ansible_root"])
        environment = job.runtime_environment(root)
        self.assertEqual(environment["HOME"], str(root.parent / "home"))
        self.assertEqual(environment["PYTHONNOUSERSITE"], "1")
        self.assertEqual(environment["ANSIBLE_COLLECTIONS_PATH"], str(root.parent / "collections"))
        self.assertEqual(environment["ANSIBLE_COLLECTIONS_SCAN_SYS_PATH"], "false")
        self.assertEqual(environment["ANSIBLE_LOCAL_TEMP"], str(job.LOCAL_TEMP))
        self.assertEqual(environment["ANSIBLE_SSH_CONTROL_PATH_DIR"], str(job.LOCAL_TEMP))
        self.assertEqual(environment["TMPDIR"], environment["ANSIBLE_SSH_CONTROL_PATH_DIR"])
        self.assertNotIn(str(root.parent), environment["ANSIBLE_SSH_CONTROL_PATH_DIR"])
        for kind in job.PLUGIN_TYPES:
            self.assertEqual(environment["ANSIBLE_" + kind + "_PLUGINS"],
                             str(root.parent / "plugins" / kind.lower()))
        self.assertNotIn("PYTHONPATH", environment)
        self.assertNotIn("SSH_AUTH_SOCK", environment)

    def test_approval_issuance_disabled_without_policy_or_write(self):
        with patch.object(job, "policy_and_hash") as policy_read, \
             patch.object(job.os, "open") as opened:
            with self.assertRaisesRegex(job.Reject, "issuance disabled"):
                job.issue_approval("ubuntu_hardening", "web01", "cron_hourly", "CHG123")
            policy_read.assert_not_called()
            opened.assert_not_called()

    def test_fingerprint_covers_trusted_runtime_trees_and_effective_paths(self):
        policy_path = Mock()
        policy_path.stat.return_value.st_mode = 0o600
        rules = policy()

        def read(path):
            if path is policy_path:
                return json.dumps(rules).encode()
            if str(path).endswith("tasks/main.yml"):
                return b"  tags: [cis_2_4_1_3]\n"
            return b"trusted fixture"

        with patch.object(job, "POLICY_PATH", policy_path), \
             patch.object(job, "trusted_file", side_effect=read) as files, \
             patch.object(job.Path, "is_dir", return_value=True), \
             patch.object(job.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=1001)), \
             patch.object(job, "service_directory") as scratch, \
             patch.object(job, "release_digest", return_value=b"release") as release, \
             patch.object(job, "trusted_tree_digest", return_value=b"tree") as trees:
            _, first = job.policy_and_hash()
            release.assert_called_once_with(rules, json.dumps(rules).encode(), legacy_active=False)
            self.assertIn(job.ENTRYPOINT, [call.args[0] for call in files.call_args_list])
            scratch.assert_called_once_with(job.LOCAL_TEMP, 1001)
            changed = job.runtime_environment(Path(rules["ansible_root"]))
            changed["ANSIBLE_COLLECTIONS_PATH"] = "/different/trusted/path"
            with patch.object(job, "runtime_environment", return_value=changed):
                self.assertNotEqual(first, job.policy_and_hash()[1])
            with patch.object(job, "trusted_tree_digest", return_value=b"changed tree"):
                self.assertNotEqual(first, job.policy_and_hash()[1])
            with patch.object(job, "release_digest", return_value=b"new release"):
                self.assertNotEqual(first, job.policy_and_hash()[1])

    def test_policy_rejects_observation_only_control_even_when_role_has_tag(self):
        rules = policy()
        rules["controls"]["cron_hourly"]["tag"] = "cis_7_1_1"
        policy_path = Mock()
        policy_path.stat.return_value.st_mode = 0o600
        with patch.object(job, "POLICY_PATH", policy_path), \
             patch.object(job, "trusted_file", side_effect=lambda path: json.dumps(rules).encode() if path is policy_path else b"tags: [cis_7_1_1]"), \
             patch.object(job.Path, "is_dir", return_value=True), \
             patch.object(job.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=1001)), \
             patch.object(job, "release_digest", return_value=b"release"), \
             patch.object(job, "service_directory"):
            with self.assertRaisesRegex(job.Reject, "no reviewed remediation"):
                job.policy_and_hash()

    def test_observation_only_tags_and_renamed_controls_are_rejected(self):
        for os_name, target in (("ubuntu24", "web01"), ("debian12", "db01")):
            for control, tag in (("cron_hourly", "cis_7_1_1"),
                                 ("observation", "cis_2_4_1_3"),
                                 ("cron_hourly", "cis_2_4_1_4")):
                rules = policy()
                rules["controls"] = {control: {"tag": tag, "os": [os_name]}}
                name = "ubuntu_hardening" if os_name == "ubuntu24" else "debian_hardening"
                with self.subTest(os=os_name, control=control, tag=tag), self.assertRaises(job.Reject):
                    job.selection(rules, name, target, control)

    def test_catalog_has_seven_closed_playbooks(self):
        self.assertEqual(len(job.JOBS), 7)
        for name, (_, playbook, _) in job.JOBS.items():
            self.assertIn(name.split("_")[-1], ("preflight", "audit", "verify", "hardening"))
            self.assertTrue(playbook.endswith(".yml"))

    def test_protocol_accepts_only_four_identifiers(self):
        self.assertEqual(job.parse_wazuh(protocol(["ubuntu_hardening", "web01", "cron_hourly", "none"])),
                         ("ubuntu_hardening", "web01", "cron_hourly", "none"))
        numeric_uuid = "1fca84c0-b7ef-4a9a-a1c2-76955ff426fd"
        self.assertEqual(job.parse_wazuh(protocol(["ubuntu_hardening", "web01", "cron_hourly", numeric_uuid]))[3], numeric_uuid)
        for args in (["ubuntu_hardening", "web01", "cron_hourly"],
                     ["ubuntu_hardening", "all", "cron_hourly", "none", "--apply"],
                     ["/tmp/playbook.yml", "web01", "cron_hourly", "none"],
                     ["ubuntu_hardening", "web01,db01", "cron_hourly", "none"],
                     ["ubuntu_hardening", "web01", "all", "none"],
                     ["ubuntu_hardening", "web01", "cron_hourly", "wrong"]):
            with self.subTest(args=args), self.assertRaises(job.Reject):
                job.parse_wazuh(protocol(args))
        for raw in (b"{}\n", b"invalid\n", protocol(["ubuntu_audit", "web01", "none", "none"])[:-1],
                    b'{"version":1,"version":1}\n'):
            with self.subTest(raw=raw[:20]), self.assertRaises(job.Reject):
                job.parse_wazuh(raw)

    def test_job_target_control_matrix(self):
        rules = policy()
        for name in ("ubuntu_audit", "ubuntu_verify", "debian_audit", "debian_verify", "debian_preflight"):
            target = "web01" if name.startswith("ubuntu") else "db01"
            host, _, tag, extras = job.selection(rules, name, target, "none")
            self.assertEqual(host, target)
            self.assertEqual((tag, extras), ("", []))
        self.assertEqual(job.selection(rules, "ubuntu_hardening", "web01", "cron_hourly")[2],
                         "cis_2_4_1_3")
        for name, target, control in (("ubuntu_hardening", "db01", "cron_hourly"),
                                      ("ubuntu_hardening", "web01", "none"),
                                      ("ubuntu_audit", "web01", "cron_hourly"),
                                      ("debian_hardening", "all", "cron_hourly")):
            with self.subTest(name=name, target=target), self.assertRaises(job.Reject):
                job.selection(rules, name, target, control)

    def test_approval_is_scoped_burned_before_launch_and_not_replayable(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            approval_id = "dfca84c0-b7ef-4a9a-a1c2-76955ff426fd"
            document = {"version": 1, "job": "ubuntu_hardening", "target": "web01",
                        "control": "cron_hourly", "change_id": "CHG123", "fingerprint": "abc",
                        "expires": int(time.time()) + 60}
            source = directory / (approval_id + ".json")
            source.write_text(json.dumps(document), encoding="utf-8")
            source.chmod(0o600)
            with patch.object(job, "APPROVAL_DIR", directory), \
                 patch.object(job, "private_directory"), \
                 patch.object(job, "trusted_file", return_value=source.read_bytes()), \
                 patch.object(job, "sync_directory"):
                with self.assertRaises(job.Reject):
                    job.consume_approval(approval_id, "debian_hardening", "web01", "cron_hourly", "abc")
                self.assertTrue(source.exists())
                self.assertEqual(job.consume_approval(approval_id, "ubuntu_hardening", "web01", "cron_hourly", "abc"), "CHG123")
                self.assertFalse(source.exists())
                self.assertTrue((directory / (approval_id + ".consumed")).exists())
                with self.assertRaises(job.Reject):
                    job.consume_approval(approval_id, "ubuntu_hardening", "web01", "cron_hourly", "abc")

    def test_expired_or_changed_fingerprint_never_consumed(self):
        approval_id = "dfca84c0-b7ef-4a9a-a1c2-76955ff426fd"
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / (approval_id + ".json")
            doc = {"version": 1, "job": "ubuntu_hardening", "target": "web01",
                   "control": "cron_hourly", "change_id": "CHG123", "fingerprint": "abc",
                   "expires": int(time.time()) - 1}
            source.write_text(json.dumps(doc), encoding="utf-8")
            source.chmod(0o600)
            with patch.object(job, "APPROVAL_DIR", directory), patch.object(job, "private_directory"), \
                 patch.object(job, "trusted_file", side_effect=lambda path: source.read_bytes()):
                with self.assertRaises(job.Reject):
                    job.consume_approval(approval_id, "ubuntu_hardening", "web01", "cron_hourly", "abc")
                doc["expires"] += 120
                source.write_text(json.dumps(doc), encoding="utf-8")
                with self.assertRaises(job.Reject):
                    job.consume_approval(approval_id, "ubuntu_hardening", "web01", "cron_hourly", "changed")
                self.assertTrue(source.exists())

    def test_preview_only_and_apply_is_rejected_before_consumption(self):
        inventory = {"_meta": {"hostvars": {"web01": {"ansible_host": "192.0.2.1"},
                                              "db01": {"ansible_host": "192.0.2.2"}}},
                     "all": {"children": ["ubuntu"]},
                     "ubuntu": {"children": ["ubuntu_2404"]},
                     "ubuntu_2404": {"hosts": ["web01"]},
                     "debian_12": {"hosts": ["db01"]}}
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(job, "STATE_DIR", Path(temporary)), \
             patch.object(job.os, "geteuid", return_value=0), \
             patch.object(job.os, "getuid", return_value=0), \
             patch.object(job, "policy_and_hash", return_value=(policy(), "abc")), \
             patch.object(job, "private_directory"), \
             patch.object(job, "deployment_lock", return_value=nullcontext()), \
             patch.object(job, "inventory_groups", return_value=inventory), \
             patch.object(job, "emit") as events, \
             patch.object(job, "run_private", return_value=(0, False)) as runner, \
             patch.object(job, "consume_approval", return_value="CHG123") as consume:
            self.assertEqual(job.run_job("ubuntu_hardening", "web01", "cron_hourly", "none"), 0)
            preview = runner.call_args.args[0]
            self.assertIn("--check", preview)
            self.assertIn("--diff", preview)
            self.assertEqual(preview[preview.index("--limit") + 1], "web01")
            self.assertEqual(preview[preview.index("--tags") + 1], "cis_2_4_1_3")
            consume.assert_not_called()
            self.assertEqual(events.call_args.args[0], "completed")
            runner.reset_mock()
            with self.assertRaisesRegex(job.Reject, "apply disabled"):
                job.run_job("ubuntu_hardening", "web01", "cron_hourly",
                            "dfca84c0-b7ef-4a9a-a1c2-76955ff426fd")
            runner.assert_not_called()
            consume.assert_not_called()
            self.assertEqual(job.run_job("ubuntu_hardening", "web01", "cron_hourly", "none"), 0)
            self.assertEqual(runner.call_args.kwargs["lock_fd"] >= 0, True)
            runner.return_value = (0, True)
            self.assertEqual(job.run_job("ubuntu_hardening", "web01", "cron_hourly", "none"), 1)
            self.assertEqual(events.call_args.args[0], "failed")

    def test_inventory_requires_playbook_group_not_just_alias(self):
        graph = {"ubuntu": {"children": ["ubuntu_2404"]},
                 "ubuntu_2404": {"hosts": ["web01"]},
                 "debian_12": {"hosts": ["db01"]}}
        self.assertTrue(job.group_contains(graph, "ubuntu", "web01"))
        self.assertTrue(job.group_contains(graph, "ubuntu_2404", "web01"))
        self.assertFalse(job.group_contains(graph, "debian_12", "web01"))
        self.assertFalse(job.group_contains(graph, "ubuntu", "all"))

    def test_inventory_rejects_two_aliases_for_one_address(self):
        graph = {"_meta": {"hostvars": {"web01": {"ansible_host": "192.0.2.1"},
                                       "db01": {"ansible_host": "192.0.2.1"}}}}
        with self.assertRaises(job.Reject):
            job.unique_target_addresses(policy(), graph)

    def test_read_only_job_refuses_approval_before_launch(self):
        with patch.object(job.os, "geteuid", return_value=0), \
             patch.object(job.os, "getuid", return_value=0), \
             patch.object(job, "policy_and_hash", return_value=(policy(), "abc")), \
             patch.object(job, "run_private") as runner:
            with self.assertRaises(job.Reject):
                job.run_job("ubuntu_audit", "web01", "none",
                            "dfca84c0-b7ef-4a9a-a1c2-76955ff426fd")
            runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
