# Archive Report: complete-cis-ubuntu-debian

**Change**: complete-cis-ubuntu-debian
**Project**: ansible-linux-hardening-lab
**Archived**: 2026-09-29
**Archive status**: COMPLETE — intentional-with-warnings (orchestrator-approved archive-time stale-checkbox reconciliation; see Reconciliation section)
**Final verdict**: PASS WITH WARNINGS (verify-report, Engram obs #538) — blockers: 0, critical findings: 0, requirements 9/9, scenarios 10/10

## 1. Archive Readiness

- Native `sdd-status --json --instructions`: `dependencies.archive: ready`, `nextRecommended: archive`, `taskProgress: 12/12 complete`, `applyState: all_done`, `remediationState.required: false`.
- Action context: `mode: repo-local`, workspace root `C:\Users\Victor\Desktop\ansible_prod`; all archive operations stayed inside `allowedEditRoots`.
- `reviewOffer` was present; per contract it was not read as archive state.
- Task Completion Gate: **PASS** — the persisted tasks artifact (Engram obs #63) has all 12 implementation tasks checked; no stale unchecked tasks in the archived audit trail.

## 2. Artifacts Read (observation IDs for traceability)

| Artifact | Engram obs | Content read |
|---|---|---|
| proposal | #60 | Full |
| spec | #61 | Full — 9 requirements / 10 scenarios across five capability specs |
| design | #62 | Full |
| tasks | #63 | Full — 12/12 checked |
| apply-progress | #65 | Full — contained one stale unchecked item, reconciled at archive (section 4) |
| verify-report | #538 | Full — byte-identical copy on disk at `openspec/changes/complete-cis-ubuntu-debian/verify-report.md` |

## 3. Spec Sync (hybrid mode)

- **Engram (authoritative)**: the spec artifact obs #61 is the complete `pinned-corpus-catalog` family specification (full spec, not a delta: no ADDED/MODIFIED/REMOVED/RENAMED sections). It remains the source of truth for the five capability domains it defines: pinned-corpus-catalog (Exact catalog; Fail-closed validation), control-interface-evidence (Exhaustive disposition; Automated evidence), platform-benchmark-adapters (Semantic admission; Adapter fidelity and migration), profile-release-qualification (Aggregate qualification; Bounded claims and delivery), compatibility-lifecycle (Proof-backed retention).
- **Filesystem**: `openspec/changes/complete-cis-ubuntu-debian/specs/` contained no delta spec files and no `openspec/specs/` main-spec tree existed. The per-delta sync loop executed zero iterations; `gentle-ai sdd-archive-compose` was therefore not required and was not invoked. No spec tree was fabricated into a workspace whose `openspec/config.yaml` declares Engram authoritative without authorizing OpenSpec change artifacts.
- Verification evidence: all 9 requirements / 10 scenarios were proven COMPLIANT in verify-report obs #538 (spec compliance matrix), so the synced record and the implementation agree at close.

## 4. Apply-Progress Stale Item Reconciliation (exceptional, orchestrator-approved)

- **Stale item**: `- [ ] Semantic proof replacement/review_id recomposition remains pending.` in obs #65, written 2026-09-05 by the first firewall apply slice — it predates tasks 3.3/4.1/4.2.
- **Completion proof (ranked)**: (1) tasks artifact obs #63: all 12 tasks checked; (2) verify-report obs #538 (2026-09-29): production-documents qualification ran with `--semantic-review` and passed for both platforms (Ubuntu 311 controls/862 routes; Debian 310/860), which admits the seven-field semantic-review records and their review_ids; (3) commits 4b0d27f, 4ee6f5b, a84f69e, 7d54797 landed the work.
- **Action taken**: obs #65 updated to mark the item complete with a dated reconciliation note appended; the historical work-unit evidence table was left verbatim. The verify-report itself assigned this reconciliation to archive. Audit trail: this report.

## 5. Final State at Close

Per the Final-State Authority hierarchy, the orchestrator launch-prompt facts corroborated by repository evidence outrank intermediate snapshots:

- Firewall 4.x fully mapped: 4.4.1.x → `package_installed`/`service_disabled`; 4.3.3 / 4.3.7 / 4.4.2.x / 4.4.3.x → `manual_observation`.
- Site-specific `config_line` controls 5.3.3.2.3, 6.2.3.6, 6.2.3.21 → `manual_observation`.
- 35 previously-broken `config_line` controls completed (missing `regexp` propagated from remediation into audit/verification) after the lifecycle-proof runtime audit surfaced the defect — commit a84f69e.
- Five root-level compatibility wrapper playbooks removed (commit 7d54797); canonical `playbooks/{audit,hardening,verify}/` paths are the sole entry points.
- Qualification (verify-report obs #538, at verification time): `ROUTING_VALID corpora=2 routes=621`; `PRODUCTION_DOCUMENTS_VALID` Ubuntu 311/862 and Debian 310/860; 6/6 playbooks `--syntax-check exit=0` on the lab ansible-control VM.
- Commits (newest first): 7d54797 (remove wrappers), a84f69e (fix 35 config_line), 4ee6f5b (firewall + 3 config_line), 4b0d27f (manual observation 1.1.2.x + 1.7.x) — verified present in `git log`.
- Working tree at close: clean except untracked `openspec/changes/` (per workspace config, intentionally not git-tracked; no archive commit was made).

## 6. Store-Mode Discrepancy (recorded, not silently resolved)

- Parent-confirmed session preflight declared `artifact_store.mode: hybrid`; native `sdd-status` and `openspec/config.yaml` report `artifactStore: engram` ("declares Engram as the authoritative artifact store WITHOUT authorizing any OpenSpec change artifacts"). All native artifact locators resolved as Engram topic keys.
- Handling applied: hybrid executed **additively and conservatively** — Engram remained the authoritative artifact store (all locators, all full-content reads); filesystem work was limited to the artifact already present on disk (the untracked `verify-report.md`), moved intact to the dated archive, plus this additive `archive-report.md`. No `openspec/specs/` tree was created and nothing was git-committed.

## 7. Archive Move and Mechanical Copy Contract Evidence

- Pre-move recursive snapshot created via `cp -R` into a private `mktemp -d` snapshot root (auto-removed by EXIT trap).
- Destination-collision guard: `openspec/changes/archive/2026-09-29-complete-cis-ubuntu-debian` did not exist.
- `git mv` refused: `fatal: source directory is empty...` (exit 128 — source untracked by git; contract fallback applies). Source-vs-snapshot integrity `diff -r` before fallback: **empty**.
- Plain `mv` fallback succeeded; source directory confirmed absent afterward (`Test-Path` → False).
- MANDATORY readback `diff -r "$snapshot_root/source" "$destination"`: verbatim output between `READBACK_DIFF_BEGIN` and `READBACK_DIFF_END` markers contained **zero lines**; `READBACK_DIFF_STATUS=0`. Empty diff = byte-identity PASS.
- Destination contents after move: `verify-report.md` (SHA-256 `00FA0E3D1DFFB3904E4C7FD7B64D152DF95E242572C0DE18CD62921D2E638863`). This `archive-report.md` is additive-only and excluded from the source/destination comparison (it did not exist in the snapshot).

## 8. Archive Verification Checklist

- [x] Main specs updated correctly — vacuously true: zero on-disk deltas; Engram spec obs #61 is authoritative and unchanged (section 3).
- [x] Change folder moved to archive (`openspec/changes/archive/2026-09-29-complete-cis-ubuntu-debian/`).
- [x] Archive contains all on-disk artifacts (verify-report.md); Engram archive holds proposal #60, spec #61, design #62, tasks #63, apply-progress #65 (reconciled), verify-report #538, archive-report (this).
- [x] Archived tasks record has no unchecked implementation tasks (obs #63: 12/12).
- [x] Active changes directory no longer contains this change.
- [x] Verbatim `diff -r` readback empty (section 7).

## 9. Open Operational Note (non-blocking)

- verify-report #538 SUGGESTION asked to confirm live-VM convergence, second-run idempotency, and rollback receipts under `ansible/evidence/cis/<candidate-id>/` before archive. At archive time a filesystem search confirmed **no `evidence/` directory and no `receipt.yml`/`results.yml`/`SHA256SUMS` files exist in the repository** (searched all paths; `docs/ansible-documentation` excluded as read-only vendored docs). This is recorded as an undiagnosed-by-this-phase gap rather than silently resolved: the declared verification gate (clean-committed-candidate qualification + syntax checks) passed, blockers/critical = 0, and the orchestrator directed archive; runtime behavioral receipts remain to be produced in a lab run before any release/entrega claim beyond the bounded spec language.

## 10. Cycle Closure

The change `complete-cis-ubuntu-debian` is fully planned (proposal/spec/design/tasks), implemented (12/12 tasks, 4 final-state commit groups), verified (PASS WITH WARNINGS, 9/9 requirements, 10/10 scenarios), and archived on both hybrid store sides. The SDD cycle for this change is complete.
