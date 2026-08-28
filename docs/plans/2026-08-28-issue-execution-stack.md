# Issue execution stack

**Built** 2026-08-28 from `fix/redaction-hardening` @ `88119b5`.
**Method**: three mapping agents over the 22 open issues plus the code, one
adversarial pass over the resulting order. The red team broke six claimed
dependencies, found four missed collisions, and re-split four issues the first
draft treated as atomic. Its corrections are folded in below.

**Ordering rule**: a dependency is real only when doing B before A means REDOING
B. Topic similarity is not a dependency. Where an ordering is a judgement call
rather than a derivation, it says so.

**All line numbers are against `88119b5`**, a 3248-line `kali_pentest_server.py`.
`main` is 3117 lines; line numbers there differ.

---

## Lanes

Everything lands in one large Python file, so concurrency is safe only where
edits are far apart AND test files are disjoint. Six lanes:

| Lane | Region | Can run concurrently with |
|---|---|---|
| **A** render | `kali_pentest_server.py` 830-1150 | B, C, D, E, F |
| **B** tool argv | 2136-2400 | A, C, D, E, F |
| **C** hashcat | 2742-2768 | A, B, D, E, F |
| **D** plumbing | 356, 3142-3220 | A, B, C, E, F |
| **E** image + data | no server edit | all |
| **F** repo hygiene | GitHub only | all |

Lane A is irreducibly serial: every step edits `_render_report`.
Lanes B and C are ~350 lines apart in the same region; safe, but not the same session.

---

## W0 — Unblock. Do these before anything else.

| Item | Lane | Why here |
|---|---|---|
| Merge #27 (`fix/redaction-hardening`, 5 commits, fast-forwardable) | F | **For the CI gate, not for conflicts.** The diff is 233 lines in `kali_pentest_server.py`, all above old line ~623; no later wave edits below 760, so the "everything rebases across it" claim is FALSE. The real reason: it installs the redaction differential, the zero-collection guard and `scripts/mutation-check`, which every later PR must then pass. |
| Merge PR #16 (docs-only, MERGEABLE/CLEAN, open since 2026-08-25) | F | `docs/releases/container-build.md:22-26` says Darwin/arm64 qualification "remains pending"; `release-evidence/apple-silicon-darwin-arm64.json` is committed and says passed. A stale sentence, not a false claim. #12 has a documentation-matches-image criterion. |
| Close or relabel #2 | F | All ten children (#3-#11, #13) are closed and the code exists. A shipped PRD still labelled `ready-for-agent` will make an agent re-execute it. |

---

## W1 — Five lanes in parallel. No dependencies among them.

| Issue | Lane | Site | Note |
|---|---|---|---|
| **#47** session-killer | D | `execute_command:359` | One line: `stdin=subprocess.DEVNULL` when `input_text is None` (`subprocess.run` rejects `input=` and `stdin=` together, so it must be conditional). `capture_output=True` already pipes fds 1 and 2, so fd 0 is the ONLY inherited descriptor, and the issue's own discriminator matches: the three tools that survive don't read stdin, the three that kill the session (`sqlmap`, `hydra`, `crackmapexec`) all prompt. **Strike the concurrency bullet from the issue body** — handlers already serialize on the event loop (zero hits for `asyncio`/`to_thread`/`Semaphore`/`run_in_executor`), so a bound is dead code. |
| **#51** RecursionError | D | `_load_normalized_results:3157` | Except tuple lacks `RecursionError`; `_load_json:1998` already catches it. Route through it. |
| **#24-versions** | D | `_tool_version_metadata:1207-1222` | **Split from #24.** Dict-literal fix, keys on tool-function names while every caller passes scanner names. Measured: `["whatweb"] -> {}` but `["whatweb_scan"] -> {...}`; same for nikto, nuclei, sslscan, wafw00f. **The issue's own suggested fix is inert**: `render_combined:1060-1062` builds metadata from each result's own key and never reads `document.get("metadata")`, so attaching metadata to the combined doc ships a no-op. Outside #41's footprint; depends on nothing. |
| **#55** unbounded render | A | `render_findings:963`, `rows():975`, `render_combined:1012`, `generate_report` | **Owns the edit to `tests/test_wave2_gate.py:134`** (`assertEqual(151, ...)`), which a 100-cap breaks. Publish the cap as a module constant beside `MAX_OUTPUT_LINES` with its own bound test — otherwise #41's rewrite of `render_combined` silently drops it. |
| **#46 + #44 merged** | B | 9 sites | **#44 undercounts itself by three.** Live case-sensitive sites: `wpscan_scan:2160`, `dirb_scan:2177`, `_fuzz_target:2205`, `gobuster_scan:2258` and `:2262`, `sqlmap_scan:2300`, `whatweb_scan:2321`, `wafw00f_scan:2337`, `nuclei_scan:2351`. **`:2160` is in `wpscan_scan`, whose `:2167` is the whole of #46** — same function, so merge them. One shared scheme predicate, matching `web_headers:2426`. |
| **#56** then **#45-server** | C | `:2760-2761`, then `:2763` | **#56 owns `:2760-2761`.** #45's `--force` is at `:2763` and its own transcript shows the self-test aborts with `--force` already set, so the fix is ADDING `--self-test-disable`, not removing a flag. Three lines apart; sequence them. |
| **#15** image | E | `docker/packages.lock:38` | Needs container evidence, not a grep. The issue does NOT claim the server calls sudo; it claims the packaged amass wrapper does, internally, under `no-new-privileges`. Image layer. |
| **#45-image** | E | `docker/packages.lock` | No `pocl`/`ocl-icd`. |
| **#25a** templates | E | `nuclei-templates/`, `manifest.json` | One test pins the single-template set: `tests/test_nuclei_adapter.py:96`. Also touches manifest digests and the image verifier, so not quite "pure data". |

**#14 is deliberately NOT in W1.** See W2.

---

## W2

| Issue | Lane | Note |
|---|---|---|
| **#43** | B | After #44. #43's fix is letting `web_audit:2955` pass the target through unchanged, which makes every child's scheme logic live for the first time. Do it before #44 and `web_audit("HTTP://h")` reaches unnormalized children. Must edit the pinned contract at `tests/test_legacy_contract.py:204-224`. |
| **#26b** entries dedupe | D | **Split from #26.** `generate_report:3176`, 2100 lines from the render work. **Decide drop-vs-merge on the issue body first**: "keep newest per (scanner, target)" contradicts #41 item 5's "keep occurrence count + provenance". This is the one piece of #26 work #41 genuinely discards. |
| **#14** | B or D | After #56. The broken literal `/usr/share/wordlists/dirb/common.txt` is at FOUR sites — `:2232`, `:2252`, `:2284`, and `:2761` — and `:2761` is the line #56 deletes. #14's own AC says "**every** preserved call", so scoping it to the three fuzzers is a re-scoping of the issue, not a reading of it: **write the split onto both issue bodies before either starts.** |

---

## W3 — Lane A, after W2

| Issue | Note |
|---|---|
| **#26a + #48 + #49 merged** | All three share `render_combined:1023-1043`. #49's fix is extracting the dedupe block into a helper; doing it first means rewriting that helper for the other two. Must come after W3's scheme work: the dedupe key IS the target string. **#48 has negative coverage** — `tests/test_wave2_gate.py:152,160,164` assert the behaviour #48 changes; the fix must keep them passing while adding a differing-content case. Run **#26b before #48**: keeping only the newest result file makes #48's headline repro (failed `smbclient` then successful) disappear, shrinking #48 to the intra-document case. |

---

## W4 — Lane A + Lane E

| Issue | Note |
|---|---|
| **#28 + #24-info merged** | Both land on `render_findings:997`. #24 wants Remediation hidden on INFO, #28 wants it populated and rendered only when present — same line, so filing them apart guarantees rework. **#28 is partly fixed already, on `main` not on this branch**: `slots():913-955` maps `FixedVersion` and `PrimaryURL`/`References`. Remaining: `_parse_nikto_json:2028` drops the `See:` URL, nuclei's nested `info.reference`/`info.remediation` are never promoted, TLS parsers carry no remediation. |
| **#25b** coverage surfacing | `_run_nuclei_capture:1441`, `nuclei_scan:2355`, `_nuclei_report_versions:1256`. Untouched by #41. |

---

## W5 — Lane A

| Issue | Note |
|---|---|
| **#39 + #40 merged** | One cached-feed loader, one join by CVE id, two field groups, one "Not enriched" rule. **Enrich at render time**, not capture time. Feeds must be baked files (`Dockerfile:74,76` pattern) — but the reason is the import block (lines 3-19: `urllib.parse` only, no HTTP client) and offline runs, **not** the report CSP. The CSP at `:803` constrains the rendered page in a browser and says nothing about build-time fetching; leave that reason in and someone will "fix" the CSP. Add a **staleness threshold** to the "Not enriched" rule, or a baked feed will confidently print a months-old EPSS score. |

---

## W6 — Lane A, last of the code work

| Issue | Note |
|---|---|
| **#41** report IA | Rewrites `render_combined:1001-1091` and reshapes `_REPORT_TEMPLATE:799`. Needs #28's slots and W5's fields to exist, or its renderer is written twice. **#41 depends on #48**: its item 5 puts `evidence` in the identity, and evidence carries per-run noise (whois timestamps, `exit code N`, the truncation counter — all three proven by `tests/test_wave2_gate.py:152-169`). Without #48's noise-normalizer, #41's own identity re-inflates. Breaks `tests/test_reports.py:111,300`, `tests/test_report_browser.py`, and the `test_wave2_gate.py` ceiling test. |

---

## W7 — Release, #12

**W8 in the draft was not a wave. It is an epic with unscheduled work and no
issues filed.** #12's eight criteria cannot pass while callable tools abort
(#45/#46/#14/#15/#56) — but that is not its hardest blocker.

Structural blockers, all verified, **none of which has an issue**:

1. **No registry exists.** No container package for this repo; zero repo-wide hits for `ghcr.io` or `docker push`. `docker-bake.hcl:21` outputs a local OCI tar.
2. **The token scope forbids publishing.** `.github/workflows/container.yml:9-10` is `contents: read`. No `packages: write`, no `id-token: write`. The build uses `load: true` with no `push:`.
3. **No committed package-lock evidence.** `release-evidence/*-packages.tsv` is written and uploaded as an artifact; `git ls-files release-evidence` shows only the Apple JSON.
4. **No Linux capabilities evidence artifact.** The only `CapEff` check is an assertion inside `tests/integration/run_container_integration.py:465`. Nothing records it.
5. **AC1 cannot run in CI.** `scripts/qualify-apple-silicon:112-114` gates on Darwin/arm64, so it needs a human at physical hardware every release.

**Correction to a common misreading**: AC5 is NOT a blocker. It says "publish
digests and provenance, **or record explicit limitations**", and
`docs/releases/container-build.md:28-30` already discharges it. **AC2** is the
criterion that requires a registry.

Also: the Apple evidence file records `reference`, `digest` and `image_id` as
the same local image ID, not a registry manifest digest, and carries no VCS ref.
PR #16's own body says it must be refreshed after the writable-home launcher change.

---

## Issue bodies that must be amended before work starts

Doing these first costs minutes and prevents an agent implementing the wrong thing.

| Issue | Amendment |
|---|---|
| #47 | Strike the concurrency/semaphore bullet. Already satisfied; building it is dead code. |
| #44 | Nine sites, not five. List them. |
| #24 | Split into versions (`:1207`) and INFO-suppression (`:997`). Note the suggested fix is inert. |
| #26 | Split into #26a (target normalization) and #26b (entries dedupe). Settle drop-vs-merge. |
| #14 / #56 | Write the `:2761` boundary onto both. |
| #45 | The flag fix is adding `--self-test-disable`, not removing `--force`. |
| #12 | File the five structural blockers as their own issues. |

---

## Progress — the tracking surface

**This table is the source of truth between sessions.** Update it in the same
commit as the work, never afterwards. A row is `done` only when its check has run
and passed in that session; a row nobody verified stays `WIP` however finished it
looks.

**States**: `-` not started · `WIP` in progress · `done` landed and verified ·
`blocked` needs something named in Blocker · `n/a` closed without work.

**Rule for the next session**: read this table first, take the topmost `-` row
whose Needs column is satisfied, and set it `WIP` before touching code. Rows in
different lanes can run concurrently; rows in the same lane cannot.

**Status: W0, 0 of 22 items done.**

| # | Wave | Lane | Item | Needs | State | Landed as | Blocker |
|---|---|---|---|---|---|---|---|
| 1 | W0 | F | Merge #27 (`fix/redaction-hardening`, 5 commits) | — | - | | user says "push it" |
| 2 | W0 | F | Merge PR #16 (docs truth) | — | done | `756e199` on main | |
| 3 | W0 | F | Close or relabel #2 | — | done | closed as completed, `ready-for-agent` removed | |
| 4 | W0 | F | Amend 7 issue bodies (see table above) | — | done | #47 #44 #24 #26 #14 #56 #45 | |
| 5 | W1 | D | #47 session-killer, `execute_command:359` | 1 | - | | |
| 6 | W1 | D | #51 RecursionError, `:3157` | 1 | - | | |
| 7 | W1 | D | #24-versions, `_tool_version_metadata:1207` | 1, 4 | - | | |
| 8 | W1 | A | #55 render caps + module constant + owns `test_wave2_gate.py:134` | 1 | - | | |
| 9 | W1 | B | #46 + #44 merged, one scheme predicate, 9 sites | 1, 4 | - | | |
| 10 | W1 | C | #56 hashcat wordlist, owns `:2760-2761` | 1, 4 | - | | |
| 11 | W1 | C | #45-server, add `--self-test-disable` at `:2763` | 10 | - | | |
| 12 | W1 | E | #15 amass, image layer | 1 | - | | needs container evidence |
| 13 | W1 | E | #45-image, pocl/ocl-icd in `packages.lock` | 1 | - | | |
| 14 | W1 | E | #25a template set + manifest + `test_nuclei_adapter.py:96` | 1 | - | | |
| 15 | W2 | B | #43 `web_audit:2955` stop pre-prefixing | 9 | - | | |
| 16 | W2 | D | #26b entries dedupe, `generate_report:3176` | 4 | - | | drop-vs-merge undecided |
| 17 | W2 | B/D | #14 wordlist defaults, 3 fuzzer sites only | 10 | - | | |
| 18 | W3 | A | #26a + #48 + #49 merged, `render_combined:1023-1043` | 8, 15, 16 | - | | |
| 19 | W4 | A | #28 + #24-info merged, `:997` + `slots:913` | 18 | - | | |
| 20 | W4 | E | #25b nuclei coverage surfacing | 14 | - | | |
| 21 | W5 | A | #39 + #40 merged, render-time, baked feeds, staleness rule | 19 | - | | |
| 22 | W6 | A | #41 report IA rewrite | 19, 20, 21 | - | | |
| 23 | W7 | F | File 5 structural release blockers as issues | — | - | | |
| 24 | W7 | F | #12 release qualification | all above | - | | needs registry + token scope |

### Session log

One line per session. Append, never edit.

| Date | Session did | Rows moved |
|---|---|---|
| 2026-08-28 | Built this plan: 3 mapping agents, 1 adversarial pass. Closed #27's code work (7 commits, unmerged). | — |
| 2026-08-28 | Merged PR #16, closed #2 as completed, appended verified corrections to 7 issue bodies. | 2, 3, 4 |
