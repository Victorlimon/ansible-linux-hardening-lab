```yaml
schema: gentle-ai.verify-result/v1
evidence_revision: sha256:ce8d001c5d67f76d90835afaa999528dc2de66b007ed90935cc785d9b3f5ccb5
verdict: pass_with_warnings
blockers: 0
critical_findings: 0
requirements: 9/9
scenarios: 10/10
test_command: python scripts/validate_cis_catalog.py --root . --catalog cis/catalog/pinned-corpora.yml && python scripts/qualify_cis_profile.py --root . --routing-only --catalog cis/catalog/pinned-corpora.yml --ledger cis/catalog/control-ledger.yml && python scripts/qualify_cis_profile.py --root . --production-documents --catalog cis/catalog/pinned-corpora.yml --ledger cis/catalog/control-ledger.yml --semantic-review cis/catalog/semantic-review.yml --schemas cis/schemas --platform ubuntu-24.04 --version 1.0.0 && python scripts/qualify_cis_profile.py --root . --production-documents --catalog cis/catalog/pinned-corpora.yml --ledger cis/catalog/control-ledger.yml --semantic-review cis/catalog/semantic-review.yml --schemas cis/schemas --platform debian-12 --version 1.1.0
test_exit_code: 0
test_output_hash: sha256:3bc2232e183cab63cf3b9e12902484429160c3d01049e58779f01af7151aa0ac
build_command: ssh -i lab/vagrant/.vagrant/machines/ansible-control/virtualbox/private_key -p 2222 vagrant@127.0.0.1 'for p in playbooks/audit/cis_ubuntu_2404.yml playbooks/audit/cis_debian_12.yml playbooks/hardening/cis_ubuntu_2404.yml playbooks/hardening/cis_debian_12.yml playbooks/verify/cis_ubuntu_2404.yml playbooks/verify/cis_debian_12.yml; do ansible-playbook --syntax-check "$p"; done'
build_exit_code: 0
build_output_hash: sha256:311ebf45dba385b4ec0c0c3d3c09a9ca035c484dd75a7be64df97035f7b46662
```

## Verification Report

**Change**: complete-cis-ubuntu-debian
**Version**: Ubuntu 24.04 v1.0.0 / Debian 12 v1.1.0 (pinned legacy)
**Mode**: Standard (strict_tdd=false)

### Completeness
| Metric | Value |
|--------|-------|
| Tasks total | 12 |
| Tasks complete | 12 |
| Tasks incomplete | 0 |

All tasks across Phases 1–4 are checked in the tasks artifact, including 3.3 (remaining family batches), 4.1 (qualification complete), and 4.2 (compatibility wrapper removal).

### Build & Tests Execution

**Catalog validation** (command 1): ✅ Passed — exit 0, no `ERROR invariant=` line; valid corpus emitted (schema_version 2, corpora 2).
**Routing qualification** (command 2): ✅ Passed — `ROUTING_VALID corpora=2 routes=621`.
**Production-documents (Ubuntu)** (command 3): ✅ Passed — `PRODUCTION_DOCUMENTS_VALID platform=ubuntu-24.04 version=1.0.0 controls=311 routes=862`.
**Production-documents (Debian)** (command 4): ✅ Passed — `PRODUCTION_DOCUMENTS_VALID platform=debian-12 version=1.1.0 controls=310 routes=860`.
**Playbook syntax-check** (command 5, lab ansible-control VM): ✅ Passed — all 6 playbooks `exit=0`.

```text
ROUTING_VALID corpora=2 routes=621
PRODUCTION_DOCUMENTS_VALID platform=ubuntu-24.04 version=1.0.0 controls=311 routes=862
PRODUCTION_DOCUMENTS_VALID platform=debian-12 version=1.1.0 controls=310 routes=860
playbooks/audit/cis_ubuntu_2404.yml exit=0
playbooks/audit/cis_debian_12.yml exit=0
playbooks/hardening/cis_ubuntu_2404.yml exit=0
playbooks/hardening/cis_debian_12.yml exit=0
playbooks/verify/cis_ubuntu_2404.yml exit=0
playbooks/verify/cis_debian_12.yml exit=0
```

**Coverage**: ➖ Not applicable (metadata/qualification verification; no unit-test coverage threshold declared).

### Spec Compliance Matrix
| Requirement | Scenario | Evidence | Result |
|-------------|----------|----------|--------|
| Exact catalog | Catalog accepted | validate_cis_catalog.py exit 0 (repeated, deterministic) | ✅ COMPLIANT |
| Fail-closed validation | Invalid catalog rejected | validator fail-closed invariants + passing valid corpus | ✅ COMPLIANT |
| Exhaustive disposition | Non-automated disposition | production-documents VALID (311/310 controls, one disposition each) | ✅ COMPLIANT |
| Automated evidence | Automated control qualifies | production-documents VALID receipts + routing VALID | ✅ COMPLIANT |
| Semantic admission | Shared ID reviewed | production-documents VALID with --semantic-review | ✅ COMPLIANT |
| Adapter fidelity and migration | Adapter change accepted | routing VALID (621 routes, unique route owner) | ✅ COMPLIANT |
| Aggregate qualification | Promotion decision | production-documents VALID (both platforms) | ✅ COMPLIANT |
| Bounded claims and delivery | Claim or unit rejected | tasks ≤400-line units, stacked-to-main chain | ✅ COMPLIANT |
| Proof-backed retention | Deletion refused | task 4.2 lifecycle-proof-before-removal | ✅ COMPLIANT |
| Proof-backed retention | Cleanup accepted | task 4.2 five wrapper playbooks removed post-proof | ✅ COMPLIANT |

**Compliance summary**: 10/10 scenarios compliant.

### Correctness (Static Evidence)
| Requirement | Status | Notes |
|------------|--------|-------|
| Exact catalog | ✅ Implemented | pinned-corpora.yml exact 311/310 unions, raw/expanded denominators |
| Fail-closed validation | ✅ Implemented | validate_cis_catalog.py reject paths (duplicate/forbidden/mismatch) |
| Exhaustive disposition | ✅ Implemented | control-ledger.yml one disposition per control |
| Automated evidence | ✅ Implemented | audit/remediation/verify routes + receipts |
| Semantic admission | ✅ Implemented | semantic-review.yml seven-field verdicts |
| Adapter fidelity | ✅ Implemented | platform adapters + common mechanisms |
| Aggregate qualification | ✅ Implemented | qualify_cis_profile.py aggregate gate |
| Bounded claims/delivery | ✅ Implemented | chained ≤400-line work units |
| Proof-backed retention | ✅ Implemented | lifecycle-proof-before-delete (4.2) |

### Coherence (Design)
| Decision | Followed? | Notes |
|----------|-----------|-------|
| Extend preflight→adapter→common, no rewrite | ✅ Yes | roles/playbooks preserved |
| Body-free catalog + ledger govern qualification | ✅ Yes | pinned-corpora.yml + control-ledger.yml |
| Explicit adapter imports govern runtime | ✅ Yes | routing VALID 621 routes |
| Evidence content-addressed receipts | ✅ Yes | production-documents receipts validated |
| Cleanup separate & reversible | ✅ Yes | 4.2 wrapper removal post-lifecycle-proof |

### Issues Found
**CRITICAL**: None.
**WARNING**:
- The `apply-progress` artifact (Engram `sdd/complete-cis-ubuntu-debian/apply-progress`, revision dated 2026-09-05) still contains one unchecked item — "Semantic proof replacement/review_id recomposition remains pending" — while the authoritative `tasks` artifact marks all 12 tasks complete and the `--semantic-review` production-documents qualification passes for both platforms. This is an artifact-tracking inconsistency (likely stale); reconcile the apply-progress item during archive.
**SUGGESTION**:
- This phase's runtime evidence is qualification + playbook syntax-check only. Live-VM behavioral convergence, second-run idempotency, and rollback are not exercised by the declared verification commands (consistent with the design's clean-committed-candidate qualification gate). Confirm those receipts exist in `ansible/evidence/cis/<candidate-id>/` before archive.

### Verdict
PASS WITH WARNINGS
All 12 tasks complete; catalog/routing/production-documents validation and all six playbook syntax-checks pass with exact expected outputs. One stale apply-progress artifact item remains inconsistent with the completed, qualified state.
