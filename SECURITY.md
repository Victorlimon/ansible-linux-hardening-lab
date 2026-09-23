# Security policy

## Supported scope

Support status and exclusions are owned exclusively by
[`docs/SUPPORT.md`](docs/SUPPORT.md). This policy does not define a competing
support matrix.

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

Use an authorized control node, reviewed inventory, verified host keys, a
non-root remote identity, explicit `--limit`, and explicit tags. The Vagrant
`ansible-control` node and local inventory are laboratory examples, not
production requirements. Begin with a control-specific check-mode simulation;
protect `--diff` output because it may contain sensitive configuration.
