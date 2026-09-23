#!/usr/bin/env python3
"""Generate the pinned body-free CIS catalog from private local inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import NoReturn

PROFILES = ("server_l1", "server_l2", "workstation_l1", "workstation_l2")
PROFILE_PATTERNS = {
    "server_l1": r"Level\s*1\s*-\s*Server",
    "server_l2": r"Level\s*2\s*-\s*Server",
    "workstation_l1": r"Level\s*1\s*-\s*Workstation",
    "workstation_l2": r"Level\s*2\s*-\s*Workstation",
}
STATUS_RE = re.compile(r"\((Automated|Manual)\)\s*Profile Applicability:", re.I)
ID_RE = re.compile(r"(?<![\d.])([1-7](?:\.\d+){1,4})(?![\d.])")
LINE_ID_RE = re.compile(r"(?m)^\s*([1-7](?:\.\d+){1,4})(?=\s)")
DESCRIPTION_RE = re.compile(r"(?:^|\s)Description:\s*", re.I)
PACKAGE = {
    "manifest_sha256": "653879e7bd4bc7390c9b747eea499d61a57242ccfb959c9e4b19035f09bc8009",
    "report_sha256": "c55429c1c4d53aae6caca968bd9395e379e23cea04c57d089338f6952e426f20",
    "temporary_builder_sha256": "50308dbf1237fa49c0f4764e7bfecaa31733e05385ff1bce0971d306356f2175",
}
CONFIG = {
    "ubuntu": {
        "platform": "ubuntu-24.04", "version": "1.0.0", "source_set": "fe55ec6a2b082d43242290cdae6b222cdc1e52aad6725d85492dc8af6a2968cf",
        "document": "cis-ubuntu-linux-24.04-private-corpus", "chunks": 30,
        "counts": (311, 250, 61, 244, 64, 250, 311, 244, 308),
        "source_hashes": (
            "0290b8d2414ff0f6d058e6ad49029f6f3fcca0146ef8d77907a81b693d1a2ca4", "0c5beb61a45776f3cacd8022f2948110f7c752c2458bb829b32d05dd1edb033f",
            "0d9bd73f71b7c8b88b9c838136fd7cf6732af353ef5b50bf2964a4628b340483", "13a75a984864f2ccf470217c3abec6a68be5a5e310c7744bb0a47151f59f5c71",
            "153f3651c661bb86c1de6d17cc4e383ddec901fd0cc0ee8c3c3794d5a62bce6c", "2edb867fcfabee05a484451df15b1163f249912b4af6a0458c428f1d75872e78",
            "33d376dea11ff8c80f3c54aeab742a4adcdd53a9341117f40deaa50fcc6d9f4f", "377a164d4f6cdfa2ed00d1c1879766d94b9780440bd377bee8607e43daf8e352",
            "452acafa897bdaf2ca018912b7ca00c7d5c6878fffd20c8de1333b0bdea1e49d", "4cfff4bd04162c6e640661563da852cd0a9499cf6ce71bb352d53e510f0d6624",
            "4e3998f14c0ca227ac7752b425cd0dbbcc3bd398e04e741f26f324e872e7f675", "522e467765d46b839e52bbd2396a28bdd2ec619eba73224c323056b89b3ce17f",
            "6c08ddcd56696ace18cad8b309ef12e8690ade4ebda94c5a55fe576a40c70a80", "6cf77452854ec30681e0f055c283a902591d48a97e42dcad3243c2b2c5a43dad",
            "7674353488a9b57db9d03dddfdef60f1571be6aadbf8a3795604eff283df5675", "7ad1619f6f3b0f50adfa406f9976d9bf10a096d874efe5a9a7c1ce3538b68c87",
            "7bd7c39a5cc3ab78eb14c53566b3adab23d020705a9938e68a37f44a18e6cdf3", "7e95f053d6bb0d039e4dd71666688247fb58e2dd984fed6e97ec87f9c45ce4a8",
            "873f1b4856a4e3c820f24594f06807378fd7aca11c30eaadbb80b5b4bc65a709", "87d17e1f0b143404ab81f58d23ce1fdc0615db1f18f1613604a3401a1ac07fb8",
            "9b52eaa6e8e8206472119314ee3bc8646cceb553c33387427ea424cf9b357290", "a570d7a9667c7209234ca9d0045845bb4549f2485047ab3eecf0b5914efa606c",
            "a6cab7af64c2d10705793b6c9dded96d3a8870c2bbdcfaebf7a12b207131c95b", "dcea6c3cb3e720a546957362f3e1de0ce6a2e42d347c3894dd537c3050af57fb",
            "e1e88d252bbc7b42235c69f006b011dde8587dcdaba2420de58da39a4beff62b", "ea7aa74cff870d46bd3e50eddf98175ef0bfb105b99139225ab645a80c11d949",
            "eaabfb72ec594c34824dfcd7d106ec797ce9eaa01f76649cd2f9c25f41fa92af", "efd8f94e0a2e089d521dbd4d10868cba1a169dcbe0c2f31766f4cb10675777c5",
            "f1e6056203a42e523d821312b6fc11c41b295bbc14cfd2c7d96271090fb8c2c3", "ffd3022b0251b723c46d1d0f364b53af09939df15534d22dffc7219ecd047e88",
            "67824e5c9e5b49f1d53bd712d685c902e235807998f812353874eb1c513c0550", "8d63da5ec38733ce36d1c79c0da5ecd7c22041822869259724a3511e19f22148"
        ),
    },
    "debian": {
        "platform": "debian-12", "version": "1.1.0", "source_set": "e5f2fa90c4d02e8e4a7f4720cae8857cba799332a1e9e3e47908244f6944fc14",
        "document": "cis-debian-linux-12-private-corpus", "chunks": 35,
        "counts": (310, 248, 62, 242, 65, 248, 310, 242, 307),
        "source_hashes": (
            "38b4a9fb17c337f627f700b5fddecc1eee260d885a962750709cce4fe97edf0f", "5692e225964cd4675fcf8e4fa0da334135d986198a876298ca66d8d995cfe098",
            "5a1d0eaeb7dbe9e6f94a63a37f2cfe8f772ef086bcceea74e18579edbcd9e660", "996e47a993c5f26114cac074af97994b27671f324928b1595c2b1832d72cd91d",
            "afbba038422c995f1bd90c3490131b6dc20a83017d39b483d0045a80b4e45f11", "bb89e25256a5cf3fb90549ceaa9a4ce5bbec19328c6723daa04562094267911f",
            "ebae466533fb56b5f043b27dc2b3f921a470ec3e93024c34a2cf8f4e0ac82d36"
        ),
    },
}


class GeneratorError(Exception):
    pass


def fail(code: str) -> NoReturn:
    raise GeneratorError(code)


class BoundedParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        fail("GENERATOR_ARGUMENT_INVALID")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def source_specs(values: list[str]) -> list[tuple[int, Path]]:
    result = []
    for value in values:
        section, separator, path = value.partition("=")
        if not separator or section not in tuple(str(number) for number in range(1, 8)) or not path:
            fail("GENERATOR_SOURCE_SPEC_INVALID")
        result.append((int(section), Path(path)))
    return result


def parse_sources(platform: str, values: list[str]) -> tuple[list[dict[str, object]], list[str]]:
    specs = source_specs(values)
    raw_inputs: list[str] = []
    actual_hashes: list[str] = []
    controls: dict[str, dict[str, object]] = {}
    for section, path in specs:
        raw = path.read_bytes()
        actual_hashes.append(digest(raw))
        text = raw.decode("utf-8")
        raw_inputs.append(text)
        markers = list(STATUS_RE.finditer(text))
        previous_end = 0
        for index, marker in enumerate(markers):
            if platform == "ubuntu":
                start = text.rfind("\n", previous_end, marker.start()) + 1
                candidates = list(ID_RE.finditer(text, start, marker.start()))
                candidates = [item for item in candidates if item.group(1).startswith(f"{section}.")]
                candidate = candidates[0] if candidates else None
            else:
                start = max(previous_end, marker.start() - 1000)
                candidates = list(LINE_ID_RE.finditer(text, start, marker.start()))
                candidates = [item for item in candidates if item.group(1).startswith(f"{section}.")]
                candidate = candidates[-1] if candidates else None
            if candidate is None:
                fail("GENERATOR_RECORD_BOUNDARY_INVALID")
            end = markers[index + 1].start() if index + 1 < len(markers) else len(text)
            description = DESCRIPTION_RE.search(text, marker.end(), end)
            applicability = text[marker.end():description.start() if description else end]
            raw_profiles = [name for name in PROFILES if re.search(PROFILE_PATTERNS[name], applicability, re.I)]
            if not raw_profiles:
                fail("GENERATOR_PROFILE_INVALID")
            control_id = candidate.group(1)
            if control_id in controls:
                fail("GENERATOR_DUPLICATE_CONTROL")
            expanded = set(raw_profiles)
            if "server_l1" in expanded:
                expanded.add("server_l2")
            if "workstation_l1" in expanded:
                expanded.add("workstation_l2")
            controls[control_id] = {"raw": raw_profiles, "expanded": [name for name in PROFILES if name in expanded]}
            previous_end = marker.end()
    if sorted(actual_hashes) != sorted(CONFIG[platform]["source_hashes"]):
        fail("GENERATOR_SOURCE_IDENTITY_MISMATCH")
    ordered = [{"id": key, **controls[key]} for key in sorted(controls, key=lambda item: tuple(map(int, item.split("."))))]
    return ordered, raw_inputs


def assert_counts(platform: str, controls: list[dict[str, object]]) -> None:
    raw = [sum(name in control["raw"] for control in controls) for name in PROFILES]
    expanded = [sum(name in control["expanded"] for control in controls) for name in PROFILES]
    if (len(controls), *raw, *expanded) != CONFIG[platform]["counts"]:
        fail("GENERATOR_DENOMINATOR_MISMATCH")


def array_lines(values: list[str], chunk_size: int) -> list[str]:
    chunks = [values[index:index + chunk_size] for index in range(0, len(values), chunk_size)]
    return ["      " + ",".join(json.dumps(item) for item in chunk) + ("," if index + 1 < len(chunks) else "") for index, chunk in enumerate(chunks)]


def render_corpus(platform: str, controls: list[dict[str, object]]) -> str:
    config = CONFIG[platform]
    fingerprint = "sha256:" + config["source_set"]
    lines = ["{", '  "controls": [']
    for index, control in enumerate(controls):
        value = {"id": control["id"], "memberships": {"expanded": control["expanded"], "raw": control["raw"]}, "source_fingerprint": fingerprint, "status": "selected"}
        lines.append("    " + json.dumps(value, separators=(",", ":")) + ("," if index + 1 < len(controls) else ""))
    generator_name = "build_evidence.py;manifest=sha256:" + PACKAGE["manifest_sha256"]
    if platform == "debian":
        generator_name += ";report=sha256:" + PACKAGE["report_sha256"]
    lines.extend(["  ],", '  "generator":' + json.dumps({"name": generator_name, "version": "1.0.0;script=sha256:" + PACKAGE["temporary_builder_sha256"]}, separators=(",", ":")) + ",", '  "platform":' + json.dumps(config["platform"]) + ",", '  "profiles": {'])
    for profile_index, profile in enumerate(PROFILES):
        raw = [control["id"] for control in controls if profile in control["raw"]]
        expanded = [control["id"] for control in controls if profile in control["expanded"]]
        lines.append(f'    "{profile}":{{"expanded":[')
        lines.extend(array_lines(expanded, config["chunks"]))
        lines.append(f'    ],"expanded_count":{len(expanded)},"raw":[')
        lines.extend(array_lines(raw, config["chunks"]))
        lines.append(f'    ],"raw_count":{len(raw)}}}' + ("," if profile_index + 1 < len(PROFILES) else ""))
    document_id = config["document"] + ";input-set=" + fingerprint
    if platform == "debian":
        document_id += ";manifest=sha256:" + PACKAGE["manifest_sha256"]
    lines.extend(["  },", '  "schema_version":1,', '  "source_identity":' + json.dumps({"document_id": document_id, "edition": config["version"], "fingerprint": fingerprint}, separators=(",", ":")) + ",", '  "version":' + json.dumps(config["version"]), "}"])
    return "\n".join(lines)


def privacy_overlap(source_texts: list[str], outputs: str) -> int:
    words = lambda value: re.findall(r"[a-z0-9]+", value.lower())
    output_words = words(outputs)
    output_ngrams = {tuple(output_words[index:index + 12]) for index in range(max(0, len(output_words) - 11))}
    overlaps = set()
    for text in source_texts:
        source_words = words(text)
        overlaps.update(tuple(source_words[index:index + 12]) for index in range(max(0, len(source_words) - 11)) if tuple(source_words[index:index + 12]) in output_ngrams)
    return len(overlaps)


def run() -> int:
    parser = BoundedParser(add_help=True)
    parser.add_argument("--ubuntu-source", action="append", required=True)
    parser.add_argument("--debian-source", action="append", required=True)
    parser.add_argument("--catalog-output", required=True, type=Path)
    parser.add_argument("--provenance-output", required=True, type=Path)
    args = parser.parse_args()
    ubuntu, ubuntu_text = parse_sources("ubuntu", args.ubuntu_source)
    debian, debian_text = parse_sources("debian", args.debian_source)
    assert_counts("ubuntu", ubuntu)
    assert_counts("debian", debian)
    catalog = '{\n  "schema_version":2,\n  "corpora":[\n' + render_corpus("ubuntu", ubuntu) + ",\n" + render_corpus("debian", debian) + '\n  ]\n}\n'
    catalog_value = json.loads(catalog)
    canonical_value = {"schema_version": 2, "corpora": sorted(catalog_value["corpora"], key=lambda item: (item["platform"], item["version"]))}
    canonical = json.dumps(canonical_value, sort_keys=True, separators=(",", ":")) + "\n"
    ubuntu_canonical = json.dumps(catalog_value["corpora"][0], sort_keys=True, separators=(",", ":")) + "\n"
    script_hash = digest(Path(__file__).read_bytes())
    provenance = {
        "schema_version": 1,
        "generator": {"name": "generate_cis_catalog.py", "version": "1.0.0", "sha256": script_hash},
        "inputs": {name: {"source_count": len(CONFIG[name]["source_hashes"]), "source_sha256": sorted(CONFIG[name]["source_hashes"]), "source_set_sha256": CONFIG[name]["source_set"]} for name in ("ubuntu", "debian")},
        "outputs": {"catalog_sha256": digest(catalog.encode()), "canonical_sha256": digest(canonical.encode()), "ubuntu_canonical_sha256": digest(ubuntu_canonical.encode())},
        "counts": {name: {"unique": CONFIG[name]["counts"][0], "raw": list(CONFIG[name]["counts"][1:5]), "expanded": list(CONFIG[name]["counts"][5:9])} for name in ("ubuntu", "debian")},
        "upstream_package": PACKAGE,
        "privacy": {"forbidden_fields": 0, "source_12_word_ngram_overlap_count": privacy_overlap(ubuntu_text + debian_text, catalog), "source_content_persisted": False},
    }
    if provenance["privacy"]["source_12_word_ngram_overlap_count"]:
        fail("GENERATOR_PRIVACY_OVERLAP")
    args.catalog_output.write_text(catalog, encoding="utf-8")
    args.provenance_output.write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


def main() -> int:
    try:
        return run()
    except GeneratorError as error:
        print(f"ERROR invariant={error}", file=sys.stderr)
    except Exception:
        print("ERROR invariant=GENERATOR_INPUT_INVALID", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
