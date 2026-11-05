# Wazuh CIS v1.0.0 — Delta layer

This directory holds the delta that aligns the lab nodes with the **CIS benchmark
edition bundled inside Wazuh 4.12.0** (`cis_debian12`, `cis_ubuntu24-04`), which
is based on *CIS Debian Family Linux v1.0.0 (2020)* / *CIS Ubuntu 24.04*.

The repository baseline in `ansible/` implements the newer **CIS v1.1.0** local
benchmark (`backups-limpia/docs/`). The two editions differ on a handful of
requirements, so this delta is applied **after** the baseline.

## What it does

Reuses the shared mechanisms in `ansible/` and adds only the checks the Wazuh
edition requires beyond the baseline:

- Force `/etc/modprobe.d/<mod>.conf` (`install <mod> /bin/true|false` +
  `blacklist <mod>`) for every policy module, even when the module has no `.ko`
  on the running kernel.
- SSH hardening: `X11Forwarding no`, `AllowTcpForwarding no`.
- Single-user mode authentication (`sulogin`) + a `chage -M 365 root` guard.
- Remove legacy clients and their real binaries (`inetutils-telnet`, `tnftp`).
- rsyslog install/enable/start + `$FileCreateMode 0640`.
- journald log rotation (plain integer keys).
- logrotate `create 0640`.
- AppArmor file-backed profiles → enforce.

## Apply order

1. `ansible/` (baseline CIS v1.1.0).
2. `wazuh-cis/` (this delta).

The order matters: the two editions disagree on a few values (e.g. Ubuntu's
v1.0.0 policy requires `install /bin/false` while the baseline writes
`/bin/true`), so the delta must run last.

## Measured result

After the delta, the Wazuh SCA scores are (lab, with documented lab exceptions):

| Node | Score |
| --- | --- |
| Debian 12 | 75% |
| Ubuntu 24.04 | 70% |

Remaining non-100% failures are structural or documented (firewall engine
UFW/iptables vs nftables, kernel built-in modules, AppArmor kernel stubs, and
single-disk lab partitions/time-sync exceptions). See `MAPPING.md` for the
per-check disposition.

## Layout

- `roles/wazuh_sca_delta/` — the delta role.
- `playbooks/wazuh_delta.yml`, `playbooks/wazuh_rescan.yml`.
- `inventory/lab/hosts.yml` — LAB only; production uses a separate inventory.
- `MAPPING.md` — Wazuh check ID ↔ CIS control ↔ disposition.
- `docs/PREPRODUCCION.md`, `docs/PRODUCCION.md`.
- `scripts/sca_report.ps1` — query the Wazuh SCA score.
