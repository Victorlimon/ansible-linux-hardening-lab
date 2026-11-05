# CIS v2.0.0 — Future edition (placeholder)

CIS released the v2.0.0 edition of the Linux benchmarks. This edition is **not
yet adopted** by this repository; Wazuh will ship its own v2.0.0 SCA policy in a
future release.

## Status

- **Exists upstream:** CIS v2.0.0 and the forthcoming Wazuh SCA policy.
- **Not yet implemented here:** this directory is a placeholder so the edition
  has a stable location in the versioned layout.

## Adoption plan (when Wazuh ships the v2.0.0 policy)

1. Drop the Wazuh v2.0.0 SCA policy file into the manager `ruleset/sca/` and
   enable it (as done for v1.0.0).
2. Create `benchmarks/cis-v2.0.0/MAPPING.md` mapping each v2.0.0 check ID to a
   shared mechanism in `ansible/roles/cis_linux_common/tasks/mechanisms/`.
3. Implement only the controls that are **new** or **changed** in v2.0.0 as a
   delta role under `wazuh-cis/` (or a new `cis-v2.0.0/` layer), reusing the
   existing mechanisms.
4. Re-run the SCA scan and measure the score.

## Known v2.0.0 considerations

- v2.0.0 restructures control IDs and adds/removes some controls versus v1.x.
- Platform firewalling and kernel built-in modules remain structural decisions;
  they are documented per-edition rather than silently re-chosen.
