"""Source-only checks; real filesystem cases require local POSIX root."""

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from integration.wazuh import execution_state as state
from integration.wazuh import launch_claim as claims
from integration.wazuh import retained_observation as retained
from integration.wazuh.tests.test_retained_observation import properties


REQUEST = "01234567-89ab-4cde-8123-456789abcdef"
BOOT = "abcdef01-2345-4678-9abc-def012345678"
APPROVAL = "fedcba98-7654-4321-8abc-def012345678"


def identity():
    return state.pending_record(REQUEST, BOOT, "synthetic", "completion", "a" * 64,
                                job_id="synthetic_job", approval_id=APPROVAL)


def binding():
    return {"identity": identity(), "invocation_id": "b" * 32,
            "runtime_max_seconds": 65, "timeout_stop_seconds": 2}


class ContractTests(unittest.TestCase):
    def test_v2_pending_and_retained_compatibility(self):
        state.validate_record(identity())
        self.assertEqual(retained.classify(identity(), binding(), properties(), BOOT),
                         "retained_success")
        for key, value in (("job_id", "../bad"), ("approval_id", None),
                           ("version", True), ("unit", "other.service")):
            with self.subTest(key=key), self.assertRaises(state.Blocked):
                state.validate_record({**identity(), key: value})

    def test_read_pending_precedes_write_and_no_event_expected_argument(self):
        with patch.object(state, "read_pending", return_value=identity()) as read:
            with patch.object(state, "_create_marker") as write:
                claims.claim(REQUEST, binding())
                read.assert_called_once_with(REQUEST, state.PENDING_DIR)
                write.assert_called_once_with(binding(), REQUEST, claims.CLAIM_DIR)
        with self.assertRaises(TypeError):
            claims.claim(REQUEST, binding(), expected=identity())

    def test_every_binding_identity_dimension_must_match_disk(self):
        with patch.object(state, "read_pending", return_value=identity()):
            with patch.object(state, "_create_marker") as write:
                for key in identity():
                    candidate = {**binding(), "identity": {**identity(), key: "different"}}
                    with self.subTest(key=key), self.assertRaises(state.Blocked):
                        claims.claim(REQUEST, candidate)
                write.assert_not_called()

    def test_legacy_marker_or_unavailable_pending_never_writes(self):
        legacy = state.pending_record(REQUEST, BOOT, "synthetic", "completion", "a" * 64)
        for failure in (legacy, FileNotFoundError(), state.Blocked("damaged")):
            options = {"side_effect": failure} if isinstance(failure, Exception) else {"return_value": failure}
            with patch.object(state, "read_pending", **options), patch.object(state, "_create_marker") as write:
                with self.assertRaises((state.Blocked, OSError)):
                    claims.claim(REQUEST, binding())
                write.assert_not_called()

    def test_no_launcher_cleanup_or_retry_api(self):
        for name in ("main", "launch", "retry", "recover", "remove", "unlink"):
            self.assertFalse(hasattr(claims, name))


@unittest.skipUnless(os.name == "posix" and getattr(os, "geteuid", lambda: -1)() == 0,
                     "requires POSIX root for real ownership/openat/fsync tests")
class FilesystemTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory(prefix="wazuh-claim-test-", dir="/root")
        self.addCleanup(scratch.cleanup)
        root = Path(scratch.name)
        self.pending = root / "pending"
        self.claims = root / "claims"
        self.pending.mkdir(mode=0o700)
        self.claims.mkdir(mode=0o700)
        self.marker = self.claims / (REQUEST + ".json")
        self.options = {"pending_directory": self.pending, "claim_directory": self.claims}
        state.reserve(identity(), self.pending)

    def claim(self):
        return claims.claim(REQUEST, binding(), **self.options)

    def test_exact_roundtrip_permissions_and_fsync_order(self):
        calls = []
        sync, write = os.fsync, os.write
        def synced(fd):
            calls.append("directory" if os.path.isdir(f"/proc/self/fd/{fd}") else "file")
            return sync(fd)
        def written(fd, data):
            calls.append("write")
            return write(fd, data)
        with patch.object(state.os, "fsync", side_effect=synced), patch.object(state.os, "write", side_effect=written):
            self.claim()
        self.assertEqual(calls, ["directory", "write", "file", "directory"])
        self.assertEqual(claims.read_claim(REQUEST, **self.options), binding())
        self.assertEqual(self.marker.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            self.claim()

    def test_concurrent_duplicate_has_exactly_one_winner(self):
        def attempt(_):
            try:
                self.claim()
                return True
            except FileExistsError:
                return False
        with ThreadPoolExecutor(max_workers=4) as pool:
            self.assertEqual(sum(pool.map(attempt, range(8))), 1)

    def test_each_fsync_failure_retains_a_consumed_request(self):
        sync = os.fsync
        for failing_index in (1, 2, 3):
            count = 0
            def injected(fd):
                nonlocal count
                count += 1
                if count == failing_index:
                    raise OSError("injected sync failure")
                return sync(fd)
            with patch.object(state.os, "fsync", side_effect=injected):
                with self.assertRaises(OSError):
                    self.claim()
            self.assertTrue(self.marker.exists())
            with self.assertRaises(FileExistsError):
                self.claim()
            self.marker.unlink()  # Fixture cleanup only; never a recovery API.

    def test_short_and_zero_writes(self):
        write = os.write
        with patch.object(state.os, "write", side_effect=lambda fd, data: write(fd, data[:7])):
            self.claim()
        self.assertEqual(claims.read_claim(REQUEST, **self.options), binding())
        self.marker.unlink()
        with patch.object(state.os, "write", return_value=0):
            with self.assertRaises(state.Blocked):
                self.claim()
        with self.assertRaises(FileExistsError):
            self.claim()

    def test_hostile_entries_and_changed_pending_never_authorize_read(self):
        self.marker.symlink_to("/etc/passwd")
        with self.assertRaises(FileExistsError):
            self.claim()
        with self.assertRaises(OSError):
            claims.read_claim(REQUEST, **self.options)
        self.marker.unlink()
        self.claim()
        for mode in (0o644, 0o660):
            self.marker.chmod(mode)
            with self.assertRaises(state.Blocked):
                claims.read_claim(REQUEST, **self.options)
        self.marker.chmod(0o600)
        pending = self.pending / (REQUEST + ".json")
        pending.write_text(pending.read_text().replace(APPROVAL, REQUEST))
        with self.assertRaises(state.Blocked):
            claims.read_claim(REQUEST, **self.options)


if __name__ == "__main__":
    unittest.main()
