# Security policy

## Supported scope

- Ubuntu 24.04: released project implementation.
- Debian 12: explicitly gated canary controls only.

The project automates hardening controls but does not certify CIS compliance.

## Reporting a vulnerability

Do not open a public issue containing credentials, private keys, target details
or exploitable configuration. Report privately to the repository owner and
include only the minimum sanitized evidence needed to reproduce the issue.

## Secret response

If a credential enters Git, deleting the working-tree file is not sufficient:

1. revoke or rotate the credential;
2. remove its authorization from every target;
3. scan the working tree and all Git refs;
4. coordinate an approved history rewrite when the repository was shared;
5. rebuild disposable laboratory systems that trusted the credential.

The historical laboratory key under `lab/vagrant/ssh/` must be treated as
compromised until rotation and history cleanup are completed.

## Operational safety

Run Ansible only from `ansible-control`, use the local inventory and an explicit
`--limit`. Begin with control-specific `--check --diff`; protect resulting logs
because diffs may contain sensitive configuration.
