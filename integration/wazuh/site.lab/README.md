# Lab site

Lab-only site configuration for the VirtualBox lab (192.168.56.0/24). Built from `site.example/`.

# Site directory template

Copy this directory into the institution's **private** Git repository (the
"site repo") and replace every fictitious value. `build_release.py` combines it
with the project tree into a release bundle. Nothing here is read by Wazuh:
Wazuh only sends identifiers; this directory is the only place where hosts,
addresses and variables are defined.

| Path | Purpose |
| --- | --- |
| `inventory/hosts.yml` | Ansible inventory. Required groups: `ubuntu`, `ubuntu_2404`, `debian_12`. A host alias must not equal a group name. Addresses use the RFC 5737 documentation range. |
| `inventory/group_vars/all.yml` | `cis_execution_environment` (`lab`, `staging`, `production`) and the production gate. |
| `inventory/group_vars/ubuntu_2404.yml` | Ubuntu 24.04 policy: `cis_ubuntu_2404_sshd_allow_users` (CIS 5.1.4, must include `ansible_user`), firewall sources/rules, section switches. |
| `inventory/group_vars/debian_12.yml` | Debian 12 policy: `cis_debian_12_sshd_allow_users`, banner switches. |
| `inventory/host_vars/<alias>.yml` | Optional per-host overrides (not included in the example). |
| `policy/jobs.json` | Gateway policy subset: `service_user`, the approved `targets` (policy id to inventory alias and OS) and the reviewed `controls`. The installer derives the release paths and `release_id` itself. |
| `policy/profiles.json` | Sealed profile catalog. The single release key `@RELEASE_ID@` is replaced by the release id at build time. `inventory_profiles` are what an order's `inventory_profile_id` selects; every alias must be a `jobs.json` host of the same platform. |

## Rules enforced by `build_release.py`

- Only `inventory/` and `policy/` (plus README and Git metadata) are allowed.
- No symbolic links, binary files, private keys, vault-encrypted content,
  `ansible_password` / `ansible_become_password` style variables, or literal
  values for keys named like `*password*`, `*secret*`, `*token*`, `*api_key*`.
  Use `--allow-key NAME` only after reviewing a false positive.
- `ansible_ssh_private_key_file`, if set, must be
  `/var/lib/ansible-wazuh/ssh/id_rsa` (installed on the controller, never in a
  bundle). Host keys are checked against
  `/var/lib/ansible-wazuh/ssh/known_hosts`; `StrictHostKeyChecking=no` is
  refused outside `--allow-lab-ssh-options`.
- Become passwords cannot be shipped. Privilege escalation on managed nodes
  must work non-interactively for the automation account; record any exception
  to CIS 5.2.4 in the institution's own risk register.

## Workflow

1. Edit this directory in the site repo and commit it (review as for code).
2. Build: `python build_release.py --repo-root <project> --site <site> --release-id <new_id> --out <dir> --collections <dir>`.
3. Copy the `.tar.gz` and `.sha256` to the controller and run
   `install_controller.py release`. A release id is single-use: any change,
   including a rollback, needs a new id.
