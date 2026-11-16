#!/usr/bin/env python3
"""Install the manager-side Wazuh pieces for the ansible-job integration.

Run on the Wazuh manager host (package install) or on the Docker host
(``--docker-container NAME``). It:
  1. copies config/ansible_job_rules.xml to <ossec>/etc/rules/ (wazuh:wazuh 0660),
  2. adds config/ansible_job_command.xml to ossec.conf (idempotent),
  3. tests the configuration with ``wazuh-analysisd -t`` and rolls back on failure,
  4. restarts the manager (unless --no-restart).

Standard library only; ``--dry-run`` changes nothing. The agent side is handled
by install_controller.py bootstrap.
"""

from __future__ import annotations

import argparse
import posixpath
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

OSSEC = "/var/ossec"
RULES_NAME = "ansible_job_rules.xml"
COMMAND_PRESENT = re.compile(r"<name>\s*ansible-job\s*</name>")
_COMMENT = re.compile(r"<!--.*?-->", re.S)
CONTAINER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
OWNER = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}:[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}\Z")
MODE = re.compile(r"[0-7]{3,4}\Z")


class ManagerError(Exception):
    """Installation stopped; the previous configuration was restored."""


def merge_block(conf: str, snippet: str, present: re.Pattern) -> tuple[str, bool]:
    """Insert ``snippet`` before the last </ossec_config> unless already present."""
    masked = _COMMENT.sub(lambda match: " " * len(match.group()), conf)
    if present.search(masked):
        return conf, False
    body = "\n".join(("  " + line.rstrip()) if line.strip() else ""
                     for line in snippet.strip("\n").splitlines())
    close = masked.rfind("</ossec_config>")
    if close == -1:
        return conf.rstrip("\n") + "\n\n<ossec_config>\n" + body + "\n</ossec_config>\n", True
    head = conf[:close].rstrip(" \t")
    if not head.endswith("\n"):
        head += "\n"
    return head + "\n" + body + "\n" + conf[close:], True


def validate_xml(text: str) -> None:
    body = re.sub(r"^\s*<\?xml[^>]*\?>", "", text)
    try:
        ET.fromstring("<wazuh_root>" + body + "</wazuh_root>")
    except ET.ParseError as exc:
        raise ManagerError(f"not well-formed XML: {exc}") from exc


class Target:
    """Where the manager lives: the local host or a Docker container."""

    def __init__(self, container: str | None, dry_run: bool):
        self.container, self.dry_run = container, dry_run

    def _wrap(self, argv: list[str]) -> list[str]:
        return ["docker", "exec", "-i", self.container, *argv] if self.container else argv

    def run(self, argv: list[str], *, data: bytes | None = None, check: bool = True):
        result = subprocess.run(self._wrap(argv), input=data, capture_output=True, check=False)
        if check and result.returncode != 0:
            raise ManagerError(f"command failed ({result.returncode}): {' '.join(argv)}\n"
                               + result.stderr.decode("utf-8", "replace")[:800])
        return result

    def read(self, path: str) -> str | None:
        result = self.run(["cat", path], check=False)
        return result.stdout.decode("utf-8") if result.returncode == 0 else None

    def attributes(self, path: str) -> tuple[str, str] | None:
        """Return (owner:group, mode) of an existing regular file, or None when absent."""
        result = self.run(["stat", "-c", "%U:%G %a %F", path], check=False)
        if result.returncode != 0:
            return None
        fields = result.stdout.decode("utf-8", "replace").strip().split(" ", 2)
        if (len(fields) != 3 or not OWNER.fullmatch(fields[0]) or not MODE.fullmatch(fields[1])
                or not fields[2].startswith("regular")):
            raise ManagerError(f"{path} is not a regular file with readable attributes")
        return fields[0], fields[1]

    def write(self, path: str, data: bytes, mode: str, *, like: str | None = None) -> None:
        """Replace ``path`` atomically through an unpredictable temporary file.

        The replaced file keeps its owner, group and mode (``like`` names another file to
        copy them from, e.g. a backup of ossec.conf). A file that does not exist yet gets
        ``wazuh:wazuh`` and ``mode``.
        """
        existing = self.attributes(like or path)
        owner, final_mode = existing if existing else ("wazuh:wazuh", mode)
        directory = posixpath.dirname(path) or "."
        temporary = self.run(["mktemp", "-p", directory, ".ansible-job.XXXXXX"]
                             ).stdout.decode("utf-8", "replace").strip()
        if not temporary.startswith(directory.rstrip("/") + "/.ansible-job.") or "\n" in temporary:
            raise ManagerError("mktemp returned an unexpected path")
        try:
            self.run(["sh", "-c", 'cat > "$1"', "sh", temporary], data=data)
            self.run(["chown", "-h", owner, temporary])
            self.run(["chmod", final_mode, temporary])
            self.run(["mv", "-f", temporary, path])
        except BaseException:
            self.run(["rm", "-f", temporary], check=False)
            raise


def install(target: Target, config_dir: Path, restart: bool) -> None:
    rules = (config_dir / RULES_NAME).read_bytes()
    command = (config_dir / "ansible_job_command.xml").read_text(encoding="utf-8")
    validate_xml(rules.decode("utf-8"))
    validate_xml(command)
    rules_path = f"{OSSEC}/etc/rules/{RULES_NAME}"
    conf_path = f"{OSSEC}/etc/ossec.conf"
    original = target.read(conf_path)
    if original is None:
        raise ManagerError(f"cannot read {conf_path}: is this the Wazuh manager?")
    validate_xml(original)
    merged, changed = merge_block(original, command, COMMAND_PRESENT)
    validate_xml(merged)
    previous_rules = target.read(rules_path)
    if previous_rules is None:
        rules_state = "install"
    else:
        rules_state = "unchanged" if previous_rules.encode("utf-8") == rules else "update"
    print(f"rules file: {rules_state}")
    print(f"ossec.conf command block: {'add' if changed else 'already present'}")
    if target.dry_run:
        print("dry run complete: no change made")
        return
    try:
        if previous_rules is None or previous_rules.encode("utf-8") != rules:
            target.write(rules_path, rules, "660")
        if changed:
            target.write(conf_path + ".bak-ansible-job", original.encode("utf-8"), "660",
                         like=conf_path)
            target.write(conf_path, merged.encode("utf-8"), "660")
        test = target.run([f"{OSSEC}/bin/wazuh-analysisd", "-t"], check=False)
        if test.returncode != 0:
            raise ManagerError("wazuh-analysisd -t rejected the configuration:\n"
                               + test.stderr.decode("utf-8", "replace")[-800:])
    except (ManagerError, OSError, subprocess.SubprocessError):
        if changed:
            target.write(conf_path, original.encode("utf-8"), "660")
        if previous_rules is None:
            target.run(["rm", "-f", rules_path], check=False)
        elif previous_rules.encode("utf-8") != rules:
            target.write(rules_path, previous_rules.encode("utf-8"), "660")
        print("configuration rolled back", file=sys.stderr)
        raise
    if restart:
        if target.container:
            target.run([f"{OSSEC}/bin/wazuh-control", "restart"])
        else:
            target.run(["systemctl", "restart", "wazuh-manager"])
        print("manager restarted")
    else:
        print("restart skipped: restart the manager to load the rules")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--docker-container", metavar="NAME",
                        help="manager runs in this container (docker exec / wazuh-control)")
    parser.add_argument("--config-dir", type=Path, default=Path(__file__).resolve().parent / "config")
    parser.add_argument("--no-restart", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    if args.docker_container and not CONTAINER.fullmatch(args.docker_container):
        print("invalid container name", file=sys.stderr)
        return 2
    try:
        install(Target(args.docker_container, args.dry_run), args.config_dir, not args.no_restart)
    except (ManagerError, OSError) as exc:
        print("manager installation refused: " + str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
