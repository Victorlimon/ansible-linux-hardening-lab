import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest


MODULE_PATH = Path(__file__).resolve().parents[1] / "evidence_reconcile.py"
SPEC = importlib.util.spec_from_file_location("evidence_reconcile", MODULE_PATH)
evidence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evidence)

REQUEST = "be2e4f55-b24c-450e-b413-869a12ab9382"
RUNNER = "ec57c72d-8cc9-4946-9363-7c9d7b969022"


def agent(status, host="debian12", section="cron_daily", **extra):
    record = {"timestamp": "2026-10-05T01:00:00+00:00", "source": evidence.SOURCE,
              "request_id": REQUEST, "status": status, "host": host,
              "section": section, "mode": "check"}
    if status == "completed":
        record["timestamp"] = "2026-10-05T01:01:00+00:00"
        record["runner_request_id"] = RUNNER
    record.update(extra)
    return record


def alert(status, *, request_id=REQUEST, rule=None, host="debian12",
          section="cron_daily", agent_id="001", **extra):
    data = {"timestamp": "2026-10-05T01:01:00+00:00" if status == "completed"
            else "2026-10-05T01:00:00+00:00", "source": evidence.SOURCE,
            "request_id": request_id, "status": status, "host": host,
            "section": section, "mode": "check"}
    if status == "completed":
        data["runner_request_id"] = RUNNER
    data.update(extra)
    return {"id": "different-alert-id", "agent": {"id": agent_id},
            "rule": {"id": rule or evidence.RULES[status]}, "data": data,
            "full_log": "SECRET: never show or parse"}


class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.events = [agent("accepted"), agent("completed")]
        self.alerts = [alert("accepted"), alert("completed")]

    def check(self, expected, *, events=None, alerts=None, index=None):
        result = evidence.reconcile(self.events if events is None else events,
                                    self.alerts if alerts is None else alerts,
                                    REQUEST, index)
        self.assertEqual(result[0], expected)
        return result

    def test_manager_and_index_confirmation_use_data_request_id_not_alert_id(self):
        self.check("manager_confirmed")
        self.check("indexer_confirmed", index=list(self.alerts))

    def test_each_catalog_pair_is_supported(self):
        for host, section in evidence.PAIRS:
            with self.subTest(host=host, section=section):
                events = [agent("accepted", host, section), agent("completed", host, section)]
                alerts = [alert("accepted", host=host, section=section),
                          alert("completed", host=host, section=section)]
                self.check("indexer_confirmed", events=events, alerts=alerts, index=alerts)

    def test_missing_or_late_alert_never_claims_indexer_confirmation(self):
        self.check("incomplete", alerts=[self.alerts[0]])
        self.check("manager_confirmed", index=[self.alerts[0]])
        # A later export containing the second alert can be reconciled again.
        self.check("indexer_confirmed", index=list(self.alerts))

    def test_failed_rejected_missing_duplicate_or_out_of_order_agent_events(self):
        cases = [[self.events[0]], [agent("accepted"), agent("failed")],
                 [agent("rejected")], self.events + [agent("completed")],
                 [agent("completed", timestamp="2026-10-04T23:00:00+00:00"),
                  agent("accepted")],
                 [agent("accepted"), agent("completed", runner_request_id="bad")]]
        for events in cases:
            with self.subTest(events=events):
                self.check("incomplete", events=events)

    def test_wrong_pair_mode_source_and_unknown_catalog(self):
        cases = [[agent("accepted"), agent("completed", section="cron_hourly")],
                 [agent("accepted", host="other"), agent("completed", host="other")],
                 [agent("accepted", mode="apply"), agent("completed")],
                 [agent("accepted", source="other"), agent("completed")],
                 [agent("accepted", host=[]), agent("completed")]]
        for events in cases:
            with self.subTest(events=events):
                self.check("incomplete", events=events)

    def test_manager_wrong_agent_rule_pair_mode_and_duplicates(self):
        cases = [[alert("accepted", agent_id="002"), self.alerts[1]],
                 [alert("accepted", rule="100112"), self.alerts[1]],
                 [alert("accepted", section="cron_hourly"), self.alerts[1]],
                 [alert("accepted", mode="apply"), self.alerts[1]],
                 self.alerts + [alert("completed")],
                 self.alerts + [alert("failed", rule="100113")]]
        for alerts in cases:
            with self.subTest(alerts=alerts):
                self.check("incomplete", alerts=alerts)

    def test_manager_completed_runner_must_match_agent(self):
        for runner in (None, REQUEST, "not-a-uuid"):
            with self.subTest(runner=runner):
                completed = alert("completed")
                if runner is None:
                    del completed["data"]["runner_request_id"]
                else:
                    completed["data"]["runner_request_id"] = runner
                self.check("incomplete", alerts=[self.alerts[0], completed])

    def test_index_completed_runner_must_match_agent_and_manager(self):
        for runner in (None, REQUEST, "not-a-uuid"):
            with self.subTest(runner=runner):
                completed = alert("completed")
                if runner is None:
                    del completed["data"]["runner_request_id"]
                else:
                    completed["data"]["runner_request_id"] = runner
                self.check("incomplete", index=[self.alerts[0], completed])

    def test_copied_event_timestamps_must_match_without_using_alert_arrival_time(self):
        late_alert = alert("completed")
        late_alert["timestamp"] = "2026-10-05T01:10:00+00:00"
        self.check("manager_confirmed", alerts=[self.alerts[0], late_alert])
        late_alert["data"]["timestamp"] = "2026-10-05T01:10:00+00:00"
        self.check("incomplete", alerts=[self.alerts[0], late_alert])

    def test_index_conflict_fails_closed_but_missing_is_manager_only(self):
        self.check("manager_confirmed", index=[])
        self.check("incomplete", index=[alert("accepted", agent_id="002")])
        self.check("incomplete", index=self.alerts + [alert("completed")])

    def test_unrelated_alerts_do_not_substitute_matching_request(self):
        self.check("incomplete", alerts=[alert("accepted", request_id=RUNNER),
                                         alert("completed", request_id=RUNNER)])
        self.check("manager_confirmed", alerts=self.alerts +
                   [alert("accepted", request_id=RUNNER)])

    def test_invalid_uuid_and_malformed_record_are_incomplete(self):
        self.assertEqual(evidence.reconcile(self.events, self.alerts, "bad")[0], "incomplete")
        malformed = agent("accepted")
        malformed["status"] = []
        self.check("incomplete", events=[malformed, agent("completed")])


class FileAndCliTests(unittest.TestCase):
    def test_jsonl_and_opensearch_export(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            agent_path, manager_path, index_path = (root / name for name in
                                                    ("agent.jsonl", "manager.jsonl", "index.json"))
            agent_path.write_text("".join(json.dumps(agent(status)) + "\n" for status in
                                          ("accepted", "completed")), encoding="utf-8")
            manager_path.write_text("".join(json.dumps(alert(status)) + "\n" for status in
                                            ("accepted", "completed")), encoding="utf-8")
            index_path.write_text(json.dumps({"hits": {"hits": [
                {"_source": alert("accepted")}, {"_source": alert("completed")}]
                }}), encoding="utf-8")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = evidence.main(["--request-id", REQUEST, "--agent-jsonl", str(agent_path),
                                      "--manager-jsonl", str(manager_path),
                                      "--index-json", str(index_path)])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out.getvalue())["status"], "indexer_confirmed")
            self.assertNotIn(REQUEST, out.getvalue())
            self.assertNotIn("SECRET", out.getvalue())
            bad_manager = alert("completed")
            bad_manager["data"]["runner_request_id"] = REQUEST
            manager_path.write_text(json.dumps(alert("accepted")) + "\n" +
                                    json.dumps(bad_manager) + "\n", encoding="utf-8")
            with contextlib.redirect_stdout(out := io.StringIO()):
                code = evidence.main(["--request-id", REQUEST, "--agent-jsonl", str(agent_path),
                                      "--manager-jsonl", str(manager_path),
                                      "--index-json", str(index_path)])
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(out.getvalue())["status"], "incomplete")
            manager_path.write_text("".join(json.dumps(alert(status)) + "\n" for status in
                                            ("accepted", "completed")), encoding="utf-8")
            bad_index = alert("completed")
            bad_index["data"]["runner_request_id"] = REQUEST
            index_path.write_text(json.dumps({"hits": {"hits": [
                {"_source": alert("accepted")}, {"_source": bad_index}]}}), encoding="utf-8")
            with contextlib.redirect_stdout(out := io.StringIO()):
                code = evidence.main(["--request-id", REQUEST, "--agent-jsonl", str(agent_path),
                                      "--manager-jsonl", str(manager_path),
                                      "--index-json", str(index_path)])
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(out.getvalue())["status"], "incomplete")
            index_path.write_text(json.dumps({"aggregations": {}}), encoding="utf-8")
            with contextlib.redirect_stdout(out := io.StringIO()):
                code = evidence.main(["--request-id", REQUEST, "--agent-jsonl", str(agent_path),
                                      "--manager-jsonl", str(manager_path),
                                      "--index-json", str(index_path)])
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(out.getvalue())["status"], "incomplete")

    def test_missing_export_duplicate_keys_and_partial_jsonl(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.jsonl"
            with self.assertRaises(evidence.EvidenceError):
                evidence.parse_jsonl(path)
            path.write_text('{"request_id":"x","request_id":"y"}\n', encoding="utf-8")
            with self.assertRaises(evidence.EvidenceError):
                evidence.parse_jsonl(path)
            path.write_text('{"request_id":"x"}', encoding="utf-8")
            with self.assertRaises(evidence.EvidenceError):
                evidence.parse_jsonl(path)


if __name__ == "__main__":
    unittest.main()
