# Support and evidence policy

This page is the **single normative authority** for project support status,
evidence requirements, and claim boundaries. If another document conflicts with
this page, use this page and treat the conflict as a documentation defect.

## Current support status

| Platform | Architecture | State | Qualified scope | Evidence and version | Tested commit | Access/test date | Verification dimensions |
|---|---|---|---|---|---|---|---|
| Ubuntu 24.04 Server | `x86_64` | **Released for the qualified subset** | Controls 2.4.1.2, 3.1.1 (`MANUAL` observation), 3.3.10, and 7.1.1 only, with their cumulative gates; see the [control matrix](CIS_CONTROL_MATRIX.md) | Project convergence records; official CIS catalog lists Ubuntu 24.04 LTS Benchmark 2.0.0, but no authorized recommendation body was used for current exact metadata | `dc2da95bf67b42925e2b4737c39c75c3c9a99acf` | 2026-09-04 | Exact OS/architecture preflight, syntax and task/tag discovery, bounded check-mode preview, real convergence, second-run idempotency, assertions, access, services, and reboot-sensitive checks where recorded |
| Debian 12 Server | `x86_64` | **Canary** | Explicitly selected controls only; remediation requires the Debian global and canary gates | Private, non-redistributable Debian 12 Benchmark 1.1.0 evidence for selected controls; official CIS catalog currently lists 2.0.0 | `dc2da95bf67b42925e2b4737c39c75c3c9a99acf` | 2026-09-04 | Exact OS/architecture preflight, audit/remediation/verification separation, negative gates, check mode, convergence, second-run idempotency, assertions, and connectivity |
| Docker hosts, daemon/runtime, images, and running containers | — | **Unsupported** | No project execution path is admitted | Responsibility boundaries researched only; no pinned Engine/backend test matrix | — | 2026-09-04 | None admitted |
| Ubuntu 22.04 | — | **Unsupported** | No project execution path is admitted | Official benchmark availability does not establish project support | — | 2026-09-04 | None admitted |
| Debian 11 | — | **Unsupported** | No project execution path is admitted | Official benchmark availability and lifecycle require fresh admission evidence | — | 2026-09-04 | None admitted |

“Released” never means all controls, a complete profile, or third-party
certification. The Ubuntu state is always **released for the qualified subset**.
Debian remains canary even when an individual control has successful evidence.

## Evidence semantics

A support statement must identify all of these fields:

1. exact OS release and architecture;
2. evidence source and version;
3. tested commit;
4. access or test date;
5. dimensions actually verified;
6. the selected controls, gates, and known exclusions.

Syntax checks, task/tag listing, and check mode are useful layers, not proof of
successful remediation. Check mode is a simulation and unsupported modules may
do nothing. A defensible remediation record also requires a controlled real
application, second-run `changed=0`, scope-specific assertions, access and
affected-service checks, and reboot-sensitive verification where applicable.

## Claim boundaries

Public project documentation must not:

- describe the project as benchmark-wide, certified, or independently assessed;
- promote historical task names as current exact CIS IDs, profiles, or
  assessment labels without an authorized exact-version source;
- imply support from benchmark catalog availability;
- quote, adapt, commit, host, or redistribute the local benchmark source;
- infer Docker support from generic Linux-host controls.

Use bibliographic metadata and official CIS landing pages instead of benchmark
recommendation text. The current catalog pages are the
[Ubuntu Linux Benchmarks](https://www.cisecurity.org/benchmark/ubuntu_linux),
[Debian Linux Benchmarks](https://www.cisecurity.org/benchmark/debian_linux),
and [Docker Benchmarks](https://www.cisecurity.org/benchmark/docker). Rights for
quotation, adaptation, or redistribution must be confirmed for the exact source;
they are not inferred from catalog access.

## Manual controls and operator decisions

Manual controls remain explicit. A `MANUAL` result records an observation that
requires an authorized human decision; it is not a failure, successful
remediation, or permission to change the target. Opt-in selectors and safety
gates remain cumulative and must never be inferred from a profile or section
name.

Configured firewall allow policy and observed listening services are separate
evidence dimensions:

- firewall policy records which traffic the reviewed rules intend to permit;
- listener evidence records sockets and owning services observed on the host.

An allowed port does not prove that a service is listening, and an observed
listener does not prove that the firewall permits external access. Record and
review both independently.

## Admission gates for another platform

A platform remains unsupported until all applicable gates pass:

- exact release and architecture preflight;
- authorized benchmark provenance and exact version record;
- per-control applicability, ID/profile/assessment-status, manual-input,
  remediation, and audit mapping;
- explicit section, control, and disruptive safety gates;
- syntax and task/tag discovery;
- bounded check-mode simulation followed by controlled real convergence;
- second-run idempotency and scope-specific assertions;
- access, service, and reboot-sensitive checks;
- workload regressions for Docker or other platform-sensitive workloads.

Docker admission additionally requires separate decisions and tests for host,
daemon/runtime, image-build, and running-container responsibilities, including
firewall, forwarding, storage, published ports, privilege, namespaces,
capabilities, seccomp, identity, and writable-state behavior.

## Documentation lifecycle and ownership

| Class | Meaning | Normative for current support? |
|---|---|---|
| **Current** | Maintained behavior and safe operating guidance | Yes, within its domain |
| **Reference** | Descriptive implementation detail or evidence aid | No |
| **Historical** | Dated record of what was observed or attempted | No |
| **Future** | Proposal, target architecture, or planned work | No |

Domain ownership is intentionally narrow:

- this page owns support states, taxonomy, evidence semantics, admission, and
  claim boundaries;
- [PRODUCTION_UBUNTU24.md](PRODUCTION_UBUNTU24.md) owns execution and recovery;
- [SECURITY.md](../SECURITY.md) owns vulnerability reporting and secret response;
- [CHANGELOG.md](../CHANGELOG.md), execution logs, and session records own dated
  history only;
- migration plans own future intent only;
- control matrices are reference inventories and do not establish support.

Public indexes should link here for support questions rather than restating a
competing support matrix.
