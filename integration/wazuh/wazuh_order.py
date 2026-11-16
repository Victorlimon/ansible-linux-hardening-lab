#!/usr/bin/env python3
"""Operator CLI: send a CHECK or APPLY order to the ansible-control Wazuh agent.

Builds the canonical managed-v2 order exactly as the gateway
(managed_job.parse_managed_v2) expects it and submits it through the Wazuh API
(``PUT /active-response?agents_list=<id>``). Standard library only.

The order carries identifiers only. The sole variables accepted are the three
UFW values the gateway allowlists for ``ubuntu_hardening``; there is no way to
send inventory, hosts, addresses or free variables.

The API password is read from an environment variable or an interactive prompt,
never from the command line. TLS verification is on by default.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import ipaddress
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.request
import uuid

ID = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}\Z")
HEX64 = re.compile(r"[0-9A-Fa-f]{64}\Z")
SECTION = re.compile(r"[1-7](?:\.[1-9][0-9]?)?\Z")
CONTROL_TAG = re.compile(r"cis_[0-9]+(?:_[0-9]+){2,6}\Z")
AGENT_ID = re.compile(r"[0-9]{3,}\Z")
PLAYBOOKS = ("ubuntu_hardening", "debian_hardening", "ubuntu_audit", "debian_audit",
             "ubuntu_verify", "debian_verify")
HARDENING = ("ubuntu_hardening", "debian_hardening")
SPECIAL_TAGS = ("always", "never", "all", "tagged", "untagged")
MAX_ORDER = 8192


class OrderError(ValueError):
    """The order is not acceptable to the gateway; nothing is sent."""


def identifier(value, what: str) -> str:
    if type(value) is not str or not ID.fullmatch(value) or HEX64.fullmatch(value):
        raise OrderError(f"invalid {what}: {value!r}")
    return value


def canonical_uuid(value, what: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError, TypeError) as exc:
        raise OrderError(f"invalid {what}") from exc
    if str(parsed) != value or parsed.int == 0:
        raise OrderError(f"{what} must be a lowercase hyphenated non-zero UUID")
    return value


def network(value: str, *, ssh: bool = False) -> str:
    try:
        parsed = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise OrderError(f"invalid CIDR: {value!r}") from exc
    if parsed.version != 4 or str(parsed) != value or (ssh and parsed.prefixlen == 0):
        raise OrderError(f"unapproved CIDR: {value!r}")
    return value


def parse_inbound(text: str, ssh_port: int | None) -> dict:
    """``CIDR:PORT/PROTO`` such as 10.0.0.0/24:443/tcp."""
    match = re.fullmatch(r"(.+):([0-9]{1,5})/(tcp|udp)", text)
    if not match:
        raise OrderError(f"inbound rule must look like CIDR:PORT/tcp|udp, got {text!r}")
    port = int(match.group(2))
    if not 1 <= port <= 65535 or port == (22 if ssh_port is None else ssh_port):
        raise OrderError("inbound port is invalid or equals the SSH port")
    return {"from_ip": network(match.group(1)), "port": port, "proto": match.group(3)}


def build_extra_vars(playbook: str, ssh_port: int | None, ssh_sources: list[str],
                     inbound: list[str]) -> dict:
    values: dict = {}
    if ssh_port is not None:
        if not 1 <= ssh_port <= 65535:
            raise OrderError("invalid SSH port")
        values["cis_ufw_ssh_port"] = ssh_port
    if ssh_sources:
        if len(ssh_sources) > 16:
            raise OrderError("at most 16 SSH sources")
        values["cis_ufw_ssh_allowed_sources"] = [network(item, ssh=True) for item in ssh_sources]
    if inbound:
        if len(inbound) > 32:
            raise OrderError("at most 32 inbound rules")
        values["cis_ufw_allowed_in_rules"] = [parse_inbound(item, ssh_port) for item in inbound]
    if values and playbook != "ubuntu_hardening":
        raise OrderError("firewall variables are accepted only for ubuntu_hardening")
    return values


def build_order(*, mode: str, request_id: str, change_id: str, release_id: str,
                playbook_id: str, inventory_profile_id: str, targets: list[str],
                selection_kind: str, selection_names: list[str],
                extra_vars: dict | None = None, approvals: dict | None = None) -> dict:
    if mode not in ("check", "apply"):
        raise OrderError("mode must be check or apply")
    if playbook_id not in PLAYBOOKS or (mode == "apply" and playbook_id not in HARDENING):
        raise OrderError("playbook is not allowed for this mode")
    if not 1 <= len(targets) <= 16 or len(set(targets)) != len(targets):
        raise OrderError("1..16 distinct targets required")
    targets = [identifier(item, "target") for item in targets]
    if any(item in ("all", "ungrouped") for item in targets):
        raise OrderError("broad targets are not allowed")
    if selection_kind not in ("full", "sections", "tags", "roles"):
        raise OrderError("selection kind must be full, sections, tags or roles")
    if (selection_kind == "full") != (len(selection_names) == 0) or len(selection_names) > 32 \
            or len(set(selection_names)) != len(selection_names):
        raise OrderError("full takes no names; the other kinds need 1..32 distinct names")
    for name in selection_names:
        if selection_kind == "sections":
            if type(name) is not str or not SECTION.fullmatch(name):
                raise OrderError(f"invalid section: {name!r}")
        elif selection_kind == "tags":
            if not CONTROL_TAG.fullmatch(name):
                raise OrderError(f"invalid control tag: {name!r}")
        else:
            identifier(name, "selection name")
        if name in SPECIAL_TAGS:
            raise OrderError("special tags are forbidden")
    order = {
        "mode": mode, "request_id": canonical_uuid(request_id, "request id"),
        "change_id": identifier(change_id, "change id"),
        "release_id": identifier(release_id, "release id"),
        "playbook_id": playbook_id,
        "inventory_profile_id": identifier(inventory_profile_id, "inventory profile"),
        "targets": targets,
        "selection": {"kind": selection_kind, "names": list(selection_names)},
        "extra_vars": dict(extra_vars or {}),
    }
    if mode == "apply":
        if not approvals:
            raise OrderError("apply needs one approval per host")
        order["approvals"] = {identifier(host, "approval host"): canonical_uuid(token, "approval id")
                              for host, token in approvals.items()}
    elif approvals:
        raise OrderError("check cannot carry approvals")
    return order


def canonical_json(order: dict) -> str:
    """The exact byte form the gateway compares against (sorted, compact, ASCII)."""
    text = json.dumps(order, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if len(text.encode("ascii")) > MAX_ORDER:
        raise OrderError("order exceeds 8192 bytes")
    return text


def active_response_body(order: dict) -> dict:
    return {"command": "!ansible-job", "arguments": ["managed-v2", canonical_json(order)]}


def parse_approvals(items: list[str]) -> dict:
    result = {}
    for item in items:
        host, separator, token = item.partition("=")
        if not separator or host in result:
            raise OrderError("--approval must be host=uuid, once per host")
        result[host] = token
    return result


# ------------------------------------------------------------------------ transport

def tls_context(ca_file: str | None, insecure: bool) -> ssl.SSLContext:
    if insecure:
        print("WARNING: TLS verification is DISABLED (--insecure). Lab use only.", file=sys.stderr)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    return ssl.create_default_context(cafile=ca_file)


def api_request(url: str, *, method: str, headers: dict, body: bytes | None,
                context: ssl.SSLContext, timeout: float) -> tuple[int, str]:
    request = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, context=context, timeout=timeout) as response:
            return response.status, response.read(1024 * 1024).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(65536).decode("utf-8", "replace")


def authenticate(base: str, user: str, password: str, context, timeout: float) -> str:
    token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    status, text = api_request(base + "/security/user/authenticate?raw=true", method="POST",
                               headers={"Authorization": "Basic " + token}, body=None,
                               context=context, timeout=timeout)
    if status != 200 or not text.strip():
        raise OrderError(f"authentication failed (HTTP {status})")
    return text.strip()


def send_order(args, order: dict) -> int:
    base = args.api_url.rstrip("/")
    if not base.startswith("https://"):
        raise OrderError("the API URL must use https://")
    if not AGENT_ID.fullmatch(args.agent_id):
        raise OrderError("agent id must be numeric, e.g. 001")
    user = args.user or os.environ.get("WAZUH_API_USER")
    if not user:
        raise OrderError("API user required (--user or WAZUH_API_USER)")
    password = os.environ.get(args.password_env) or getpass.getpass(f"Wazuh API password for {user}: ")
    context = tls_context(args.ca_file, args.insecure)
    jwt = authenticate(base, user, password, context, args.timeout)
    status, text = api_request(
        f"{base}/active-response?agents_list={args.agent_id}", method="PUT",
        headers={"Authorization": "Bearer " + jwt, "Content-Type": "application/json"},
        body=json.dumps(active_response_body(order)).encode("utf-8"),
        context=context, timeout=args.timeout)
    print(f"HTTP {status}")
    print(text[:2000])
    print("An HTTP acknowledgement is not evidence of execution: correlate request_id "
          f"{order['request_id']} with the terminal event and recap in Wazuh.")
    return 0 if status == 200 else 1


# ------------------------------------------------------------------------ CLI

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--api-url", default=os.environ.get("WAZUH_API_URL"),
                        help="https://manager:55000 (or WAZUH_API_URL)")
    parser.add_argument("--user", help="API user (or WAZUH_API_USER)")
    parser.add_argument("--password-env", default="WAZUH_API_PASSWORD",
                        help="environment variable holding the password (prompted if unset)")
    tls = parser.add_mutually_exclusive_group()
    tls.add_argument("--ca-file", help="CA bundle that signed the API certificate")
    tls.add_argument("--insecure", action="store_true", help="disable TLS verification (lab only)")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--print-only", action="store_true",
                        help="print the API body instead of sending it (e.g. for the API Console)")
    sub = parser.add_subparsers(dest="mode", required=True)
    for name in ("check", "apply"):
        item = sub.add_parser(name)
        item.add_argument("--agent-id", required=True, help="Wazuh id of the ansible-control agent")
        item.add_argument("--playbook", required=True, choices=PLAYBOOKS)
        item.add_argument("--release-id", required=True)
        item.add_argument("--change-id", required=True)
        item.add_argument("--inventory-profile", required=True)
        item.add_argument("--target", action="append", required=True, dest="targets",
                          metavar="ALIAS_OR_GROUP", help="repeatable")
        item.add_argument("--selection", default="full", choices=("full", "sections", "tags", "roles"))
        item.add_argument("--name", action="append", default=[], dest="names",
                          help="section (4, 5.1), control tag or role; repeatable")
        item.add_argument("--ssh-port", type=int, help="ubuntu_hardening only")
        item.add_argument("--ssh-source", action="append", default=[], metavar="CIDR")
        item.add_argument("--allow-in", action="append", default=[], metavar="CIDR:PORT/PROTO")
    sub.choices["apply"].add_argument("--request-id", required=True,
                                      help="the request id printed by the CHECK being applied")
    sub.choices["apply"].add_argument("--approval", action="append", default=[], required=True,
                                      metavar="HOST=UUID", help="one-shot approval per host")
    sub.choices["check"].add_argument("--request-id", help="optional; generated when omitted")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        request_id = args.request_id or str(uuid.uuid4())
        order = build_order(
            mode=args.mode, request_id=request_id, change_id=args.change_id,
            release_id=args.release_id, playbook_id=args.playbook,
            inventory_profile_id=args.inventory_profile, targets=args.targets,
            selection_kind=args.selection, selection_names=args.names,
            extra_vars=build_extra_vars(args.playbook, args.ssh_port, args.ssh_source, args.allow_in),
            approvals=parse_approvals(args.approval) if args.mode == "apply" else None)
        body = active_response_body(order)
        print(f"request_id: {request_id}")
        if args.print_only:
            print(json.dumps(body, sort_keys=True))
            return 0
        if not args.api_url:
            raise OrderError("API URL required (--api-url or WAZUH_API_URL)")
        return send_order(args, order)
    except (OrderError, urllib.error.URLError, ssl.SSLError, OSError) as exc:
        print("order not sent: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
