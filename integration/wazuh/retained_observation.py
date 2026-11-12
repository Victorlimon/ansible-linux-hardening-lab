"""Source-only retained-manager evidence, NOT cgroup emptiness or retirement.

Both expected identity and launch binding must come from trusted root-owned
state, never the operator/event. launch_claim persists v2 bindings; this module
does not authenticate them. The caller must exclude launches, restarts, reset-failed, stop, collection
and deployment until evidence is consumed. No gateway, launcher or CLI exists.
"""

import re
import subprocess
import time

from integration.wazuh import execution_observation as observation
from integration.wazuh import execution_state as state


RECORD_KEYS = ("version", "request_id", "boot_id", "unit", "target", "control", "release_digest")
IDENTITY_KEYS = (*RECORD_KEYS, "job_id", "approval_id")
BINDING_KEYS = {"identity", "invocation_id", "runtime_max_seconds", "timeout_stop_seconds"}
FIXED = {"LoadState": "loaded", "Type": "exec", "ExitType": "cgroup",
         "RemainAfterExit": "yes", "CollectMode": "inactive", "KillMode": "control-group",
         "Restart": "no", "Delegate": "no", "SendSIGKILL": "yes",
         "MainPID": "0", "ControlPID": "0", "NRestarts": "0", "Job": ""}
PROPERTIES = (*FIXED, "Id", "InvocationID", "ActiveState", "SubState", "Result",
              "ExecMainExitTimestampMonotonic", "RuntimeMaxUSec", "TimeoutStopUSec")
FAILURES = {"exit-code", "signal", "core-dump", "timeout"}


def _validate_binding(expected, binding):
    if (type(expected) is not dict or set(expected) != set(IDENTITY_KEYS)
            or type(binding) is not dict or set(binding) != BINDING_KEYS):
        raise state.Blocked("exact expected identity and launch binding required")
    keys = IDENTITY_KEYS if expected["version"] == 2 else RECORD_KEYS
    state.validate_record({key: expected[key] for key in keys})
    state.canonical_uuid(expected["approval_id"])
    if (type(expected["job_id"]) is not str
            or not state.IDENTIFIER.fullmatch(expected["job_id"])):
        raise state.Blocked("invalid job identity")
    if (type(binding["identity"]) is not dict or binding["identity"] != expected
            or type(binding["identity"].get("version")) is not int):
        raise state.Blocked("launch identity mismatch")
    invocation = binding["invocation_id"]
    if (type(invocation) is not str or not re.fullmatch(r"[0-9a-f]{32}", invocation)
            or int(invocation, 16) == 0):
        raise state.Blocked("launch invocation identity required")
    for key, maximum in (("runtime_max_seconds", 3600), ("timeout_stop_seconds", 60)):
        if type(binding[key]) is not int or not 1 <= binding[key] <= maximum:
            raise state.Blocked("bounded integer launch timeout required")


def _timespan(seconds):
    """Exact systemd 255 whole-second rendering; no infinity/fraction fallback."""
    parts = []
    for scale, suffix in ((3600, "h"), (60, "min"), (1, "s")):
        count, seconds = divmod(seconds, scale)
        if count:
            parts.append(f"{count}{suffix}")
    return " ".join(parts)


def classify(expected, binding, properties, boot_id):
    """Return retained_success/retained_failure or Blocked, never apply success.

    Missing cgroups are neither read nor interpreted by this independent proof.
    NRestarts rejects automatic restarts; exact launch InvocationID rejects a
    replaced/manual invocation. These checks do not replace caller exclusion.
    """
    _validate_binding(expected, binding)
    if boot_id != expected["boot_id"]:
        raise state.Blocked("launch belongs to another boot")
    if (type(properties) is not dict or set(properties) != set(PROPERTIES)
            or any(type(value) is not str for value in properties.values())):
        raise state.Blocked("complete string-valued retained properties required")
    required = {**FIXED, "Id": expected["unit"], "InvocationID": binding["invocation_id"],
                "RuntimeMaxUSec": _timespan(binding["runtime_max_seconds"]),
                "TimeoutStopUSec": _timespan(binding["timeout_stop_seconds"])}
    if any(properties[key] != value for key, value in required.items()):
        raise state.Blocked("retained unit identity or supervision mismatch")
    if not re.fullmatch(r"[1-9][0-9]{0,19}", properties["ExecMainExitTimestampMonotonic"]):
        raise state.Blocked("main exit evidence required")
    terminal = (properties["ActiveState"], properties["SubState"], properties["Result"])
    if terminal == ("active", "exited", "success"):
        return "retained_success"
    if terminal[:2] == ("failed", "failed") and terminal[2] in FAILURES:
        return "retained_failure"
    raise state.Blocked("no recognized retained terminal outcome")


def collect(expected, binding):
    """Bounded local manager reads bracketed by same-boot checks.

    Successful collection attests only this snapshot and the supplied binding;
    it does not authenticate a launch receipt or grant cleanup/retry authority.
    """
    _validate_binding(expected, binding)
    expected = dict(expected)
    binding = {**binding, "identity": dict(binding["identity"])}
    observation._require_root()
    started = time.monotonic()
    deadline = started + observation.TOTAL_SECONDS
    try:
        boot = observation._boot(deadline)
        if boot != expected["boot_id"]:
            raise state.Blocked("launch belongs to another boot")
        before = observation._parse_fields(
            observation._run_show(expected["unit"], deadline, PROPERTIES), PROPERTIES)
        outcome = classify(expected, binding, before, boot)
        after = observation._parse_fields(
            observation._run_show(expected["unit"], deadline, PROPERTIES), PROPERTIES)
        if before != after or observation._boot(deadline) != boot:
            raise state.Blocked("retained observation changed during collection")
        observation._remaining(deadline)
        return {"properties": before, "boot_id": boot, "outcome": outcome,
                "started_monotonic": started, "finished_monotonic": time.monotonic()}
    except (OSError, subprocess.SubprocessError, AttributeError) as exc:
        raise state.Blocked("retained observation unavailable") from exc
