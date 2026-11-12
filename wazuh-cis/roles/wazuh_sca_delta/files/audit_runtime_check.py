#!/usr/bin/env python3
"""Verify that every rule line of the Wazuh SCA delta file is present in the
running audit configuration (`auditctl -l`).

Rule matching is order-insensitive: auditd canonicalises syscall lists and
field order, so both the desired line and the loaded line are normalised into
a sorted token set before comparison. Exit codes:
  0  every delta rule is loaded
  1  at least one delta rule is missing (a reboot is required under -e 2)
  2  the script could not read the rules file or run auditctl
"""
import os
import subprocess
import sys

DEFAULT_RULES = "/etc/audit/rules.d/60-wazuh-sca-delta.rules"


def canon_path(path):
    real = os.path.realpath(path)
    return real if os.path.exists(real) else path


def canon_token(tok):
    if tok.startswith("/") and tok != "/":
        return canon_path(tok)
    return tok


def canon_pair(value):
    """Normalise a -F/-C field pair (auid, exit, a0, path, key...)."""
    if "=" not in value:
        return canon_token(value)
    key, _, val = value.partition("=")
    if key in ("auid", "uid", "euid", "sgid") and val == "-1":
        val = "unset"
    if key == "exit":
        val = {"-13": "-EACCES", "-1": "-EPERM"}.get(val, val)
    if key == "a0" and val.lower().startswith("0x"):
        try:
            val = str(int(val, 16))
        except ValueError:
            pass
    if key == "path":
        val = canon_path(val)
    return key + "=" + val


def normalise(line):
    tokens = line.strip().replace(",", " ").split()
    out, i = [], 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in ("-F", "-C") and i + 1 < len(tokens):
            out.append(canon_pair(tokens[i + 1]))
            i += 2
            continue
        if tok == "-k" and i + 1 < len(tokens):
            out.append("key=" + tokens[i + 1])
            i += 2
            continue
        if tok == "-p" and i + 1 < len(tokens):
            out.append("perm=" + tokens[i + 1])
            i += 2
            continue
        if tok == "-S":
            i += 1
            while i < len(tokens) and not tokens[i].startswith("-"):
                out.append("syscall=" + tokens[i])
                i += 1
            continue
        out.append(canon_token(tok))
        i += 1
    return " ".join(sorted(out))


def main():
    rules_file = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_RULES
    try:
        with open(rules_file, encoding="utf-8") as handle:
            wanted = [normalise(l) for l in handle if l.strip() and not l.strip().startswith("#")]
    except OSError as exc:
        print("cannot read %s: %s" % (rules_file, exc))
        return 2

    try:
        proc = subprocess.run(["auditctl", "-l"], capture_output=True, text=True, check=False)
    except FileNotFoundError:
        print("auditctl not found")
        return 2
    if proc.returncode != 0:
        print("auditctl -l failed: " + proc.stderr.strip())
        return 2

    loaded = {normalise(l) for l in proc.stdout.splitlines() if l.strip()}
    missing = [w for w in wanted if w not in loaded]
    for entry in missing:
        print("MISSING " + entry)
    if missing:
        print("%d/%d delta rules not loaded" % (len(missing), len(wanted)))
        return 1
    print("all %d delta rules loaded" % len(wanted))
    return 0


if __name__ == "__main__":
    sys.exit(main())
