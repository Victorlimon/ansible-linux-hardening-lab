"""Inert one-use claim persistence, never a launcher or recovery interface.

The root gateway must authenticate the manager InvocationID and hold deployment,
job and launch/restart exclusion before calling claim, until its eventual child
starts. Only a fresh successful claim call may precede that child; reading a
claim grants no launch authority. A crash or any error permanently consumes the
request when an entry exists. This module cannot establish gateway ordering.
"""

from pathlib import Path

from integration.wazuh import execution_state as state
from integration.wazuh import retained_observation as retained


CLAIM_DIR = Path("/var/lib/ansible-wazuh/launch-claims")


def _expected(request_id, pending_directory):
    expected = state.read_pending(request_id, pending_directory)
    if expected["version"] != 2:
        raise state.Blocked("v2 root-owned pending identity required")
    return expected


def claim(request_id, binding, *, pending_directory=state.PENDING_DIR,
          claim_directory=CLAIM_DIR):
    """Consume once and persist the exact binding before any eventual child.

    The expected identity is read from the private pending marker, not accepted
    from event payloads. binding must originate from a trusted root supervisor,
    not an event; validation matches it but cannot authenticate its provenance.
    O_EXCL rejects all existing entries, even corrupt or interrupted writes.
    Return only after blocker directory fsync, complete file write, file fsync,
    and directory fsync. Never delete, overwrite, retry or repair a claim.
    """
    expected = _expected(request_id, pending_directory)
    retained._validate_binding(expected, binding)
    # Snapshot the exact validated values; no mutable caller-owned identity.
    snapshot = {**binding, "identity": dict(expected)}
    retained._validate_binding(expected, snapshot)
    state._create_marker(snapshot, request_id, claim_directory)


def read_claim(request_id, *, pending_directory=state.PENDING_DIR,
               claim_directory=CLAIM_DIR):
    """Read evidence for retained observation; NEVER permission to (re)launch."""
    expected = _expected(request_id, pending_directory)
    binding = state._read_marker(request_id, claim_directory)
    retained._validate_binding(expected, binding)
    return binding
