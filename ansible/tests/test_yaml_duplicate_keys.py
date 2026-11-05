"""Focused YAML mapping-uniqueness tests for the flat variable files.

Duplicate keys inside one YAML mapping are silently resolved by the parser
(last one wins), so a redeclared control gate can drift or surprise reviewers
while the file still loads. This test parses every role defaults file and the
lab group_vars files with a strict loader that rejects duplicate keys in any
mapping, and pins the historical defect: cis_debian_12_1_6_2_issue_banner was
declared twice; it must now appear exactly once, still effective as true.

Run inside the control venv:
    python -m unittest discover -s ansible/tests -p 'test_yaml_duplicate_keys.py' -v
"""

import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
ROLES = ROOT / "ansible" / "roles"
GROUP_VARS = ROOT / "ansible" / "inventories" / "local" / "group_vars"


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader variant that raises on duplicate keys in one mapping."""


def _construct_no_duplicate_mapping(loader, node, deep=False):
    seen = {}
    for key_node, _value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        line = key_node.start_mark.line + 1
        if key in seen:
            raise yaml.YAMLError(
                f"duplicate key {key!r}: line {seen[key]} and line {line}")
        seen[key] = line
    return loader.construct_mapping(node, deep)


_StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_no_duplicate_mapping,
)


def load_strict(path):
    with path.open(encoding="utf-8") as handle:
        return yaml.load(handle, Loader=_StrictLoader)


def variable_files():
    files = sorted(ROLES.glob("*/defaults/main.yml"))
    files += sorted(GROUP_VARS.glob("*.yml"))
    return files


class YamlUniquenessTest(unittest.TestCase):
    def test_variable_files_have_no_duplicate_keys(self):
        paths = variable_files()
        self.assertGreaterEqual(len(paths), 5, "expected defaults + group_vars")
        for path in paths:
            with self.subTest(path=str(path.relative_to(ROOT))):
                document = load_strict(path)
                if document is None:
                    continue  # legitimate empty placeholder (e.g. web/database)
                self.assertIsInstance(document, dict)

    def test_debian_issue_banner_gate_declared_once_and_true(self):
        path = ROLES / "cis_debian_12" / "defaults" / "main.yml"
        text = path.read_text(encoding="utf-8")
        lines = [line for line in text.splitlines()
                 if line.startswith("cis_debian_12_1_6_2_issue_banner:")]
        self.assertEqual(
            len(lines), 1,
            "cis_debian_12_1_6_2_issue_banner must be declared exactly once")
        mapping = load_strict(path)
        self.assertIs(mapping["cis_debian_12_1_6_2_issue_banner"], True)


if __name__ == "__main__":
    unittest.main()
