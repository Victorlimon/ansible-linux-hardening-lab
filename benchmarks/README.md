# CIS Benchmark Versions

This repository tracks multiple editions of the CIS Linux benchmark. Each edition
maps to a distinct implementation layer; the shared mechanisms in `ansible/`
are reused across versions.

| Edition | Source | Implementation | Status | Git tag |
| --- | --- | --- | --- | --- |
| CIS v1.1.0 (Debian 12 / Ubuntu 24.04) | `backups-limpia/docs/` | `ansible/` | Implemented + full-verify green | `cis-v1.1.0` |
| CIS v1.0.0 (Wazuh SCA bundled) | Wazuh manager `ruleset/sca/` | `wazuh-cis/` (delta over `ansible/`) | Delta applied, SCA measured (Debian 75% / Ubuntu 70%) | `wazuh-cis-v1.0.0` |
| CIS v2.0.0 | Not yet adopted | `benchmarks/cis-v2.0.0/` (placeholder) | Planned | — |

## Versioning model

The benchmark **edition** is a catalog/mapping; the **mechanisms** are shared.

- `ansible/roles/cis_linux_common/tasks/mechanisms/` — reusable mechanisms
  (config_line, sysctl, fixed_file_permissions, kernel_module_disabled,
  mount_options, PAM stacks, account_integrity, etc.).
- Each edition contributes a mapping of its control IDs to those mechanisms
  (`ansible/cis/catalog/` for v1.1.0, `wazuh-cis/MAPPING.md` for Wazuh v1.0.0).

When a new edition is adopted, add a `benchmarks/<edition>/` directory with its
mapping and reuse the mechanisms; implement only the controls that are new or
that changed between editions.

## Apply order

1. `ansible/` (CIS v1.1.0 baseline).
2. `wazuh-cis/` (Wazuh v1.0.0 delta), because the two editions differ on a few
   requirements (e.g. Ubuntu expects `install /bin/false` where the baseline
   writes `/bin/true`).
