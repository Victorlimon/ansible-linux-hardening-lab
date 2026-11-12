"""Unit tests for sealed managed-hardening profile validation."""

from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import sys
import unittest


MODULE_PATH = Path(__file__).resolve().parents[1] / "managed_profiles.py"
SPEC = importlib.util.spec_from_file_location("managed_profiles", MODULE_PATH)
profiles = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = profiles
SPEC.loader.exec_module(profiles)
ProfileRejected = profiles.ProfileRejected
load_profile_catalog = profiles.load_profile_catalog
resolve_profile = profiles.resolve_profile


def profile_catalog() -> dict:
    return {
        "releases": {
            "lab_v10": {
                "inventory_profiles": {
                    "ubuntu_lab": {
                        "platform": "ubuntu24",
                        "aliases": ["ubuntu24"],
                    }
                },
                "host_profiles": {
                    "ubuntu24": {
                        "inventory_profile": "ubuntu_lab",
                        "platform": "ubuntu24",
                        "alias": "ubuntu24",
                    }
                },
                "section_profiles": {
                    "ssh_baseline": {
                        "host_profile": "ubuntu24",
                        "section": "ssh",
                        "tags": ["cis_5_2_1"],
                        "gates": ["ssh_access_confirmed"],
                        "disposition": "gated_unsafe",
                        "network_rules": [{
                            "service": "ssh",
                            "port": 22,
                            "protocol": "tcp",
                            "cidr": "10.20.30.0/24",
                        }],
                    }
                },
            }
        }
    }


class ManagedProfileTests(unittest.TestCase):
    def test_cron_profile_needs_no_network_rule(self):
        catalog = profile_catalog()
        catalog["releases"]["lab_v10"]["section_profiles"]["cron_hourly"] = {
            "host_profile": "ubuntu24", "section": "cron_hourly",
            "tags": ["cis_2_4_1_3"],
            "gates": ["cis_ubuntu_2404_remediation_enabled"],
            "disposition": "automated", "network_rules": [],
        }
        value = self.resolve(catalog, section_profile_id="cron_hourly")
        self.assertEqual(value.network_rules, ())

    def resolve(self, catalog=None, **overrides):
        request = {
            "release_id": "lab_v10",
            "inventory_profile_id": "ubuntu_lab",
            "host_profile_id": "ubuntu24",
            "section_profile_id": "ssh_baseline",
            "target_alias": "ubuntu24",
        }
        request.update(overrides)
        return resolve_profile(catalog or profile_catalog(), **request)

    def test_valid_ubuntu_profile_is_sealed_with_stable_digest(self):
        first = self.resolve()
        second = self.resolve()

        self.assertEqual(first.digest, second.digest)
        self.assertEqual(first.platform, "ubuntu24")
        self.assertEqual(first.target_alias, "ubuntu24")
        self.assertEqual(first.section, "ssh")
        self.assertEqual(first.network_rules[0].cidr, "10.20.30.0/24")

    def test_example_catalog_is_resolvable(self):
        catalog = load_profile_catalog(Path(__file__).parents[1] / "config" / "profiles.lab.json.example")
        self.assertEqual(self.resolve(catalog).release_id, "lab_v10")

    def test_port_boundaries_are_rejected(self):
        for port in (0, 65536):
            catalog = profile_catalog()
            catalog["releases"]["lab_v10"]["section_profiles"]["ssh_baseline"]["network_rules"][0]["port"] = port
            with self.subTest(port=port), self.assertRaisesRegex(ProfileRejected, "port must be 1..65535"):
                self.resolve(catalog)

    def test_unknown_protocol_is_rejected(self):
        catalog = profile_catalog()
        catalog["releases"]["lab_v10"]["section_profiles"]["ssh_baseline"]["network_rules"][0]["protocol"] = "icmp"

        with self.assertRaisesRegex(ProfileRejected, "unsupported protocol"):
            self.resolve(catalog)

    def test_noncanonical_or_malformed_cidr_is_rejected(self):
        for cidr in ("10.20.30.1/24", "not-a-cidr"):
            catalog = profile_catalog()
            catalog["releases"]["lab_v10"]["section_profiles"]["ssh_baseline"]["network_rules"][0]["cidr"] = cidr
            with self.subTest(cidr=cidr), self.assertRaisesRegex(ProfileRejected, "CIDR must be canonical"):
                self.resolve(catalog)

    def test_ssh_anywhere_cidr_is_rejected(self):
        for cidr in ("0.0.0.0/0", "::/0"):
            catalog = profile_catalog()
            catalog["releases"]["lab_v10"]["section_profiles"]["ssh_baseline"]["network_rules"][0]["cidr"] = cidr
            with self.subTest(cidr=cidr), self.assertRaisesRegex(ProfileRejected, "SSH CIDR /0 is forbidden"):
                self.resolve(catalog)

    def test_substituted_target_is_rejected(self):
        with self.assertRaisesRegex(ProfileRejected, "target alias does not match host profile"):
            self.resolve(target_alias="debian12")

    def test_unknown_profile_identifiers_are_rejected(self):
        with self.assertRaisesRegex(ProfileRejected, "unknown section profile"):
            self.resolve(section_profile_id="../../playbook")

    def test_manual_and_na_sections_are_blocked_from_apply(self):
        for disposition in ("manual", "na"):
            catalog = profile_catalog()
            catalog["releases"]["lab_v10"]["section_profiles"]["ssh_baseline"]["disposition"] = disposition
            with self.subTest(disposition=disposition), self.assertRaisesRegex(ProfileRejected, "not eligible for managed apply"):
                self.resolve(catalog)

    def test_digest_binds_network_gates_and_section_identity(self):
        baseline = self.resolve()
        for mutator in (
            lambda catalog: catalog["releases"]["lab_v10"]["section_profiles"]["ssh_baseline"]["gates"].append("snapshot_available"),
            lambda catalog: catalog["releases"]["lab_v10"]["section_profiles"]["ssh_baseline"]["network_rules"][0].update(cidr="10.20.31.0/24"),
        ):
            catalog = copy.deepcopy(profile_catalog())
            mutator(catalog)
            with self.subTest(mutator=mutator):
                self.assertNotEqual(baseline.digest, self.resolve(catalog).digest)


if __name__ == "__main__":
    unittest.main()
