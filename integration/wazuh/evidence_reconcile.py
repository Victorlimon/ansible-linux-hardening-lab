#!/usr/bin/env python3
"""Reconcile exported Wazuh preview evidence without contacting any service."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime
import json
import os
from pathlib import Path
import stat
import sys
import uuid


MAX_FILE_BYTES = 32 * 1024 * 1024
SOURCE = "ansible-wazuh-preview"
PAIRS = frozenset((host, section) for host in ("ubuntu24", "debian12")
                  for section in ("cron_hourly", "cron_daily"))
RULES = {"accepted": "100111", "completed": "100112"}


class EvidenceError(ValueError):
    """An exported file is unsafe or cannot be interpreted reliably."""


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("duplicate JSON key")
        result[key] = value
    return result


def read_limited(path: Path) -> str:
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise EvidenceError("export is not a regular file")
            raw = stream.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise EvidenceError("export unavailable") from exc
    if len(raw) > MAX_FILE_BYTES:
        raise EvidenceError("export too large")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvidenceError("export is not UTF-8") from exc


def parse_jsonl(path: Path) -> list[dict]:
    content = read_limited(path)
    if not content or not content.endswith("\n"):
        raise EvidenceError("JSONL is empty or lacks a final newline")
    records = []
    for line in content.splitlines():
        try:
            item = json.loads(line, object_pairs_hook=unique_object)
        except (json.JSONDecodeError, EvidenceError) as exc:
            raise EvidenceError("invalid JSONL record") from exc
        if not isinstance(item, dict):
            raise EvidenceError("JSONL record is not an object")
        records.append(item)
    return records


def parse_index(path: Path) -> list[dict]:
    try:
        data = json.loads(read_limited(path), object_pairs_hook=unique_object)
    except (json.JSONDecodeError, EvidenceError) as exc:
        raise EvidenceError("invalid index export") from exc
    if not isinstance(data, dict) or not isinstance(data.get("hits"), dict):
        raise EvidenceError("unsupported index export")
    hits = data["hits"].get("hits")
    if not isinstance(hits, list):
        raise EvidenceError("unsupported index export")
    records = []
    for hit in hits:
        if not isinstance(hit, dict) or not isinstance(hit.get("_source"), dict):
            raise EvidenceError("unsupported index hit")
        records.append(hit["_source"])
    return records


def valid_uuid(value: object) -> bool:
    try:
        return type(value) is str and str(uuid.UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


def valid_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def agent_pair(records: list[dict], request_id: str) -> tuple[tuple[str, str], str, dict] | None:
    events = [item for item in records if item.get("request_id") == request_id]
    if (len(events) != 2 or not all(type(item.get("status")) is str for item in events)
            or Counter(item["status"] for item in events) != Counter(
                {"accepted": 1, "completed": 1})):
        return None
    pair = (events[0].get("host"), events[0].get("section"))
    if not all(type(value) is str for value in pair) or pair not in PAIRS:
        return None
    for event in events:
        if (event.get("source") != SOURCE or event.get("mode") != "check"
                or (event.get("host"), event.get("section")) != pair):
            return None
    by_status = {item["status"]: item for item in events}
    accepted = valid_time(by_status["accepted"].get("timestamp"))
    completed = valid_time(by_status["completed"].get("timestamp"))
    if accepted is None or completed is None or accepted > completed:
        return None
    runner_id = by_status["completed"].get("runner_request_id")
    if not valid_uuid(runner_id) or "runner_request_id" in by_status["accepted"]:
        return None
    return pair, runner_id, by_status


def alert_rules(records: list[dict], request_id: str,
                pair: tuple[str, str], runner_id: str, events: dict) -> str:
    """Return complete, missing, or invalid for one exported alert layer."""
    matched = []
    for alert in records:
        data = alert.get("data")
        if isinstance(data, dict) and data.get("request_id") == request_id:
            matched.append(alert)
    if not matched:
        return "missing"
    found = Counter()
    for alert in matched:
        data = alert["data"]
        agent = alert.get("agent")
        rule = alert.get("rule")
        status = data.get("status")
        if (not isinstance(agent, dict) or agent.get("id") != "001"
                or not isinstance(rule, dict) or type(status) is not str
                or status not in RULES
                or str(rule.get("id")) != RULES[status]
                or data.get("source") != SOURCE or data.get("mode") != "check"
                or (data.get("host"), data.get("section")) != pair
                or data.get("timestamp") != events[status].get("timestamp")):
            return "invalid"
        if status == "completed":
            if not valid_uuid(data.get("runner_request_id")) or data["runner_request_id"] != runner_id:
                return "invalid"
        elif "runner_request_id" in data:
            return "invalid"
        found[status] += 1
    if any(count > 1 for count in found.values()):
        return "invalid"
    return "complete" if found == Counter({"accepted": 1, "completed": 1}) else "missing"


def reconcile(agent_records: list[dict], manager_records: list[dict],
              request_id: str, index_records: list[dict] | None = None) -> tuple[str, str]:
    if not valid_uuid(request_id):
        return "incomplete", "invalid_request_id"
    agent_evidence = agent_pair(agent_records, request_id)
    if agent_evidence is None:
        return "incomplete", "agent_evidence_incomplete_or_conflicting"
    pair, runner_id, events = agent_evidence
    manager = alert_rules(manager_records, request_id, pair, runner_id, events)
    if manager != "complete":
        return "incomplete", "manager_evidence_incomplete_or_conflicting"
    if index_records is None:
        return "manager_confirmed", "index_export_not_supplied"
    index = alert_rules(index_records, request_id, pair, runner_id, events)
    if index == "invalid":
        return "incomplete", "index_evidence_conflicting"
    if index == "missing":
        return "manager_confirmed", "index_evidence_missing"
    return "indexer_confirmed", "matching_exports"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Conciliar exportaciones locales de vista previa Wazuh")
    parser.add_argument("--request-id", required=True, help="UUID de la solicitud (no se imprime)")
    parser.add_argument("--agent-jsonl", required=True, type=Path)
    parser.add_argument("--manager-jsonl", required=True, type=Path)
    parser.add_argument("--index-json", type=Path, help="Respuesta OpenSearch hits.hits[*]._source")
    args = parser.parse_args(argv)
    try:
        agent = parse_jsonl(args.agent_jsonl)
        manager = parse_jsonl(args.manager_jsonl)
        index = parse_index(args.index_json) if args.index_json is not None else None
        status, reason = reconcile(agent, manager, args.request_id, index)
    except EvidenceError:
        status, reason = "incomplete", "export_missing_invalid_or_unsupported"
    print(json.dumps({"status": status, "reason": reason}, separators=(",", ":")))
    return 0 if status != "incomplete" else 1


if __name__ == "__main__":
    sys.exit(main())
