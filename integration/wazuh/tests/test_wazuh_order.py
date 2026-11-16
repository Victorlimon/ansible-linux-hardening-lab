"""The operator CLI must emit orders the sealed gateway accepts, and nothing else."""

import contextlib
import importlib.util
import io
import json
import sys
import types
import unittest
import uuid
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


order_cli = load("wazuh_order_under_test", "wazuh_order.py")
gateway = load("managed_job_for_order_test", "managed_job.py")

REQUEST = "1fca84c0-b7ef-4a9a-a1c2-76955ff426fd"
APPROVAL = "2fca84c0-b7ef-4a9a-a1c2-76955ff426fd"


def make(**changes):
    values = dict(mode="check", request_id=REQUEST, change_id="CHG_1", release_id="rel_1",
                  playbook_id="ubuntu_hardening", inventory_profile_id="ubuntu_staging",
                  targets=["ubuntu-app01"], selection_kind="sections", selection_names=["4"])
    values.update(changes)
    return order_cli.build_order(**values)


class CanonicalFormTests(unittest.TestCase):
    def accepted_by_gateway(self, order):
        raw = order_cli.canonical_json(order)
        request = gateway.parse_managed_v2(raw)
        self.assertEqual(request.request_id, order["request_id"])
        return raw, request

    def test_check_order_is_the_gateway_canonical_form(self):
        raw, request = self.accepted_by_gateway(make())
        self.assertEqual(raw, json.dumps(json.loads(raw), sort_keys=True, separators=(",", ":"),
                                         ensure_ascii=True))
        self.assertNotIn(" ", raw.replace("ubuntu-app01", ""))
        self.assertEqual((request.mode, request.selection_kind, request.selection_names),
                         ("check", "sections", ("4",)))
        self.assertTrue(raw.startswith('{"change_id":"CHG_1","extra_vars":{}'))

    def test_every_selection_kind_round_trips(self):
        for kind, names in (("full", []), ("sections", ["1", "5.1"]), ("tags", ["cis_5_1_2"]),
                            ("roles", ["cis_ubuntu_2404"])):
            with self.subTest(kind=kind):
                self.accepted_by_gateway(make(selection_kind=kind, selection_names=names))

    def test_apply_order_carries_one_approval_per_host(self):
        order = make(mode="apply", approvals={"ubuntu-app01": APPROVAL})
        _, request = self.accepted_by_gateway(order)
        self.assertEqual(request.approvals, {"ubuntu-app01": APPROVAL})

    def test_firewall_variables_follow_the_gateway_allowlist(self):
        extra = order_cli.build_extra_vars("ubuntu_hardening", 2222, ["10.20.30.0/24"],
                                           ["10.20.30.0/24:443/tcp"])
        _, request = self.accepted_by_gateway(make(extra_vars=extra))
        self.assertEqual(request.extra_vars["cis_ufw_ssh_port"], 2222)
        self.assertEqual(request.extra_vars["cis_ufw_allowed_in_rules"],
                         [{"from_ip": "10.20.30.0/24", "port": 443, "proto": "tcp"}])

    def test_active_response_body_matches_the_documented_shape(self):
        body = order_cli.active_response_body(make())
        self.assertEqual(set(body), {"command", "arguments"})
        self.assertEqual(body["command"], "!ansible-job")
        self.assertEqual(body["arguments"][0], "managed-v2")
        self.assertEqual(len(body["arguments"]), 2)
        self.assertEqual(body["arguments"][1], order_cli.canonical_json(make()))


class RejectionTests(unittest.TestCase):
    def rejected(self, **changes):
        with self.assertRaises(order_cli.OrderError):
            make(**changes)

    def test_identifier_and_uuid_rules(self):
        self.rejected(request_id="not-a-uuid")
        self.rejected(request_id=REQUEST.upper())
        self.rejected(request_id="00000000-0000-0000-0000-000000000000")
        self.rejected(change_id="has space")
        self.rejected(release_id="a" * 64)
        self.rejected(inventory_profile_id="../x")

    def test_targets_and_selection_are_bounded(self):
        self.rejected(targets=["all"])
        self.rejected(targets=["ungrouped"])
        self.rejected(targets=[])
        self.rejected(targets=["a", "a"])
        self.rejected(selection_kind="sections", selection_names=["9"])
        self.rejected(selection_kind="sections", selection_names=["4;rm"])
        self.rejected(selection_kind="tags", selection_names=["always"])
        self.rejected(selection_kind="tags", selection_names=["cis_5_1_2;x"])
        self.rejected(selection_kind="full", selection_names=["4"])
        self.rejected(selection_kind="sections", selection_names=[])
        self.rejected(selection_kind="shell", selection_names=["x"])
        self.rejected(selection_kind="roles", selection_names=["all"])

    def test_mode_rules(self):
        self.rejected(mode="apply")
        self.rejected(mode="apply", approvals={"h": "bad"}, playbook_id="ubuntu_audit")
        self.rejected(mode="check", approvals={"ubuntu-app01": APPROVAL})
        self.rejected(playbook_id="rm_rf")
        self.rejected(mode="restart")

    def test_oversized_orders_are_refused(self):
        # Reaching 8192 bytes with valid fields is impractical, so lower the cap to prove the guard.
        self.assertEqual(order_cli.MAX_ORDER, 8192)  # the gateway's own limit
        with mock.patch.object(order_cli, "MAX_ORDER", 100), self.assertRaises(order_cli.OrderError):
            order_cli.canonical_json(make())

    def test_firewall_variables_are_restricted(self):
        build = order_cli.build_extra_vars
        with self.assertRaises(order_cli.OrderError):
            build("debian_hardening", 22, [], [])
        with self.assertRaises(order_cli.OrderError):
            build("ubuntu_hardening", None, ["0.0.0.0/0"], [])
        with self.assertRaises(order_cli.OrderError):
            build("ubuntu_hardening", None, ["10.0.0.1/24"], [])
        with self.assertRaises(order_cli.OrderError):
            build("ubuntu_hardening", None, [], ["10.0.0.0/24:22/tcp"])
        with self.assertRaises(order_cli.OrderError):
            build("ubuntu_hardening", None, [], ["10.0.0.0/24:70000/tcp"])
        with self.assertRaises(order_cli.OrderError):
            build("ubuntu_hardening", None, [], ["10.0.0.0/24:80/icmp"])
        self.assertEqual(build("ubuntu_hardening", None, [], []), {})

    def test_approvals_parsing(self):
        self.assertEqual(order_cli.parse_approvals(["h1=" + APPROVAL]), {"h1": APPROVAL})
        for bad in (["h1"], ["h1=" + APPROVAL, "h1=" + APPROVAL]):
            with self.assertRaises(order_cli.OrderError):
                order_cli.parse_approvals(bad)


class CliTests(unittest.TestCase):
    ARGS = ["--print-only", "check", "--agent-id", "001", "--playbook", "ubuntu_hardening",
            "--release-id", "rel_1", "--change-id", "CHG_1", "--inventory-profile", "ubuntu_staging",
            "--target", "ubuntu-app01", "--selection", "sections", "--name", "4"]

    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = order_cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_check_generates_and_prints_a_request_id(self):
        code, out, _ = self.run_cli(self.ARGS)
        self.assertEqual(code, 0)
        request_id = out.splitlines()[0].split(": ")[1]
        self.assertEqual(str(uuid.UUID(request_id)), request_id)
        body = json.loads(out.splitlines()[1])
        self.assertIn(request_id, body["arguments"][1])
        gateway.parse_managed_v2(body["arguments"][1])

    def test_apply_requires_request_id_and_approval(self):
        base = ["--print-only", "apply", "--agent-id", "001", "--playbook", "ubuntu_hardening",
                "--release-id", "rel_1", "--change-id", "CHG_1", "--inventory-profile", "ubuntu_staging",
                "--target", "ubuntu-app01", "--selection", "sections", "--name", "4"]
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            order_cli.main(base)
        code, out, _ = self.run_cli(base + ["--request-id", REQUEST, "--approval", "ubuntu-app01=" + APPROVAL])
        self.assertEqual(code, 0)
        body = json.loads(out.splitlines()[1])
        request = gateway.parse_managed_v2(body["arguments"][1])
        self.assertEqual((request.mode, request.request_id), ("apply", REQUEST))

    def test_bad_order_exits_with_error_and_sends_nothing(self):
        with mock.patch.object(order_cli, "send_order") as send:
            code, _, err = self.run_cli(self.ARGS[:-1] + ["9"])
        self.assertEqual(code, 2)
        self.assertIn("order not sent", err)
        send.assert_not_called()

    def test_password_is_never_a_command_line_option(self):
        options = {option for action in order_cli.build_parser()._actions
                   for option in action.option_strings}
        self.assertNotIn("--password", options)
        self.assertEqual({o for o in options if "pass" in o}, {"--password-env"})
        parser = order_cli.build_parser()
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            parser.parse_args(["--password", "x", "check"])

    def test_tls_is_verified_unless_insecure_is_explicit(self):
        context = order_cli.tls_context(None, False)
        self.assertTrue(context.check_hostname)
        with contextlib.redirect_stderr(io.StringIO()) as warning:
            insecure = order_cli.tls_context(None, True)
        self.assertFalse(insecure.check_hostname)
        self.assertIn("DISABLED", warning.getvalue())

    def test_plain_http_is_refused_before_prompting(self):
        args = order_cli.build_parser().parse_args(
            ["--api-url", "http://manager:55000", *self.ARGS[1:]])
        with mock.patch("getpass.getpass") as prompt, self.assertRaises(order_cli.OrderError):
            order_cli.send_order(args, make())
        prompt.assert_not_called()

    def test_send_uses_bearer_token_and_agent_query(self):
        args = order_cli.build_parser().parse_args(
            ["--api-url", "https://manager:55000", "--user", "op", *self.ARGS[1:]])
        calls = []

        def fake(url, *, method, headers, body, context, timeout):
            calls.append((url, method, headers, body))
            return (200, "jwt-token") if "authenticate" in url else (200, '{"data":{}}')

        with mock.patch.dict("os.environ", {"WAZUH_API_PASSWORD": "pw"}), \
                mock.patch.object(order_cli, "api_request", fake), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(order_cli.send_order(args, make()), 0)
        self.assertEqual(calls[0][1], "POST")
        self.assertTrue(calls[0][2]["Authorization"].startswith("Basic "))
        self.assertEqual(calls[1][0], "https://manager:55000/active-response?agents_list=001")
        self.assertEqual(calls[1][1], "PUT")
        self.assertEqual(calls[1][2]["Authorization"], "Bearer jwt-token")
        self.assertEqual(json.loads(calls[1][3]), order_cli.active_response_body(make()))


if __name__ == "__main__":
    unittest.main()
