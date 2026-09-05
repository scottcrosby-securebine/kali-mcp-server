# State [#91 P3d shipped: merged to main 628d7f5, release HELD | 2026-09-06]

## Resume
#91 re-test/delta report (Option A) landed via PR #112 → `main` `628d7f5`; F1 repair exited the doctrine gate on two clean passes; a kali pin rot was bumped en route. Next: Scott's rulings D4/D5, then #92. Not released (`v2.1.0`, HELD).

## Active Work
| Item | Issue | Status | Key Files |
|------|-------|--------|-----------|
| Re-test/delta report + F1 | #91 | ✅ merged `628d7f5` · 🔴 NOT released (held) | `docs/specs/2026-09-02-p3d-gate-review.md` |
| D4 DF1 normalization tightening | — | ⏳ Scott's call (lowercase host in `_retest_same_target` + test; resets gate) | gate-review loop 2 |
| D5 loop-1 spec items M1/M2 M3 S1 W1 | — | ⏳ Scott's call | — |
| Exports / PCI / exec report | #92 #93 #94 | ⏳ not started; #92 next | `docs/plans/ROADMAP.md` (untracked) |
| Open bugs | #84 #79 #76 #45 | 🟡 untouched | — |

## Git State
- Branch: `main` @ `628d7f5` (ff-synced this session) | tracked clean | PRs: none
- This handoff commit is LOCAL ONLY: push needs Scott's "push it".
- Worktrees: `~/kali-worktrees/p3d` @ `a0db0b4` (merged); `p3c` @ `f95ee4b`.
- Doctrine run-state: `~/kali-worktrees/p3d-run-state.md` (outside tree).

## Runtime
- Image publish: `main` container run on `628d7f5` was in_progress; confirm it published. Release = `v*` tag, HELD.
- Targets (carried 2026-09-03, not re-observed): radstore3 `10.10.15.132`; NX1 `172.29.129.206` SSH only; DNS `10.10.15.5/.6`; pm/qb.securebine.com prod, light scans only; zonetransfer.me; crack lab `~/kali-crack-lab/` (john).

## Gotchas (learned this session)
- Codex red team may only hand-trace pasted hunks (sandbox can't read source): add one source-verified fresh-context seat.
- Cache-warm local `docker build` proves nothing about pins; Dockerfile:57 exit 123 = pin rot: bump per `a0db0b4`, verify both arches from the Packages index.
- Untracked copies of tracked docs block `pull --ff-only`; cmp, then remove.
- Carried: `/tmp` wiped; toy fixtures hide dead features; out_args argv omits the target (identity = `target_ref`); never closure vocabulary; green tests lie about runtime; redaction chokepoint `_redact_scanner_data`; no absolute-second asserts; 41 + 9 additions; check `baseRefName` before merge.

## Next Session Kickoff
1. `session-memory:primer`, then `doctrine:doctrine` + `doctrine:doctrine-code` before gated work.
2. Get Scott's rulings D4 and D5; don't start them unasked.
3. Then #92 per `docs/plans/ROADMAP.md`.
4. Rules: "push it" before push/PR/merge; no co-author lines; release HELD; review fixed point = phase-start SHA.
