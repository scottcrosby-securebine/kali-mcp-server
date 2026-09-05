# P3d gate review — seat findings (loop 1)

## Spec axis (returned)
- W2 (BLOCKING, real bug): retest_report compares two docs without enforcing
  baseline.target_ref == current.target_ref. nmap fp is host-blind (port-N-proto),
  so hostA-baseline vs hostB-current → false UNCHANGED/NEW. FIX: target equality.
- W1 (spec-vs-code): NEW/UNCHANGED/UPDATED emit on a non-comparable pair; my spec
  table said gate-fail → whole pair UNKNOWN. NOTE: presence-based verdicts are
  sound regardless of scope; only ABSENCE needs comparability. Likely spec-wording
  fix, not code. DECISION needed.
- M1/M2 (spec-vs-code): content_version never captured; gate omits content-version
  check. Vetted seed set is not template-driven, nuclei is advisory → low impact.
  Reconcile: implement or mark deferred.
- M3 (spec-vs-code): asset-set-shrink guard not implemented. Multi-host excluded
  via _retest_single_host_ok; single-host dark = ZERO_YIELD/UNKNOWN. Largely moot.
- S1 (defensible): ADVISORY is a 7th verdict (spec listed 6 + "low-confidence").
  Keep; reconcile spec wording.
- CONFIRMED not-wrong: no closure verdict reachable; ZERO_YIELD/NOT_OBSERVED-vs-
  UNKNOWN/ordering/status/argv/pre-provenance all classify correctly.

## Red team axis (returned)
- F1 (BLOCKING, reproduced): SAME as Spec-W2 and DEEPER. (1) gate never compares
  target_ref. (2) For nmap/sslscan/testssl the stored argv OMITS the target —
  _run_with_capture passes argv=cmd (base) but the target is added later in
  out_args(out_path); so nmap argv=[nmap,--unprivileged,-sT,-Pn,-F] (no target),
  sslscan argv=[sslscan] (constant). => argv-equality trivially true across
  DIFFERENT hosts => false NOT_OBSERVED_ON_RETEST. Reproduced: hostA baseline vs
  hostB current => comparable=True => port-80@A rendered NOT_OBSERVED.
  Toy-fixture masked it: NMAP_ARGV faked the target appended (capture never does).
  ROOT FIX: add target_ref equality to _retest_pair_comparable (mismatch => False,
  "different assets" => UNKNOWN). Do NOT store full argv (out_args has random /tmp
  path => never equal => all UNKNOWN). De-fixture tests to real captured argv +
  add a different-target_ref case.
- NB1-NB5 (non-blocking, all confirm solid): scanner/target substitution handled;
  fingerprint sound; multi-host guard correct (srv1-2 over-rejected, safe dir);
  redaction safe (cross-engagement /artifacts baseline not re-redacted — operator
  input, minor); path traversal + HTML injection + crash all blocked.

## CONSOLIDATED (loop 1)
ONE blocking class: F1/W2 = target identity not bound to the pair, compounded by
out_args scanners' argv omitting the target, masked by a toy fixture. Root fix =
target_ref equality in the gate + de-fixture tests. Everything else non-blocking
(spec-vs-code reconciliations M1/M2/M3/S1/W1, standards judgement smells S1-S4).
No closure claim reachable (confirmed by all seats).
PAUSED per Scott before repair round.

## Standards axis (returned)
- NO hard violations. All documented standards pass (subprocess seam, redaction
  chokepoint for argv, one-line docstring, validate->build->return str, count
  reconciliation).
- S1 (judgement, Speculative Generality): IDENTITY_FIELDS_PER_PARSER = 9x ["id"];
  the per-field loop + whitelist guard + list/None normalize branches are
  unexercised today. Defensible via opt-in plan. Ponytail: frozenset of vetted
  scanners + hash id; grow when a 2nd field is opted in. NON-BLOCKING.
- S2 (minor Duplicated Code): redact-argv expression duplicated in _capture_findings
  and nuclei_scan. Helper candidate.
- S3/S4 (low/very-minor): 'closure-free' naming; (scanner,target,finding,...) clump.

## Loop 2 — F1 repair round (e05dfbd)

Fix: `_retest_same_target` binds the pair to one normalized `target_ref`;
`_retest_classify` (sole verdict producer) short-circuits a cross-target pair to
whole-pair UNKNOWN before any presence or absence verdict; `retest_report` refuses
a cross-target pair. `_retest_pair_comparable` deliberately untouched (single caller,
below the guard, gates absence only; a guard there would not cover presence).
Tests: `NMAP_ARGV` de-fixtured to the real captured argv (no target); cross-target
classifier + tool-refusal cases added; each pins exactly its own guard (mutants).

Gate: native (712 OK, redaction 0/800, mutation-check vs f9d7d0e caught, container
verify + integration seam green) + Standards + Spec + red team, two consecutive
clean passes, zero blocking. Red team seats were same-model fresh-context critics
(codex sandbox could not read source in pass 1).

Deferred, non-blocking: DF1 guard normalizes scheme-only, weaker than the Phase-2
identity model (case / trailing-dot / name-vs-IP same-asset pairs fall to
UNKNOWN or refuse, safe direction); DF2/DF3 cosmetic row labelling on the
classify cross-target path, unreachable via the tool; DF4 both-targetless docs
pass the guard (malformed only); DF5 redaction collapses same-host
different-credential scope (pre-existing, cited non-claim only); DF6/DF7 foreign
or pre-P2 docs only. Loop-1 spec-vs-code items (M1/M2, M3, S1, W1) still await
the owner's ruling.
