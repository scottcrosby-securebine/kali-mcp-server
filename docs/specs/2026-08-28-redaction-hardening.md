# Redaction hardening (#27)

Spec and confirmed list for the retry on issue #27. Handed to reviewers by path.
Orchestrator counters live in `.scratch/redaction-hardening-runstate.md`, which
is untracked and is NOT part of what a reviewer reads.

## Anchor

The user's request, verbatim:

> start on #27 use doctrine

Carried instruction from the prior session's handoff (`SESSION_MEMORY.md`,
`## Next Session Kickoff`), verbatim:

> 2. **#27** — solo, never batched. Read the issue's "what was tried" list first;
>    needs the paired table plus a twelve-parser differential in BOTH directions.
>    Skill: `doctrine:doctrine-audit`.

> User says **"push it"** before any push. Commit identity
> `scottcrosby-securebine`; no co-author/generated-by lines (PR bodies too).
> Always use `Closes #N`.

Issue #27's own acceptance bar, verbatim from the issue body:

> Any retry must carry:
> - a PAIRED table — see `REDACTION_MUST_REMOVE` / `REDACTION_MUST_KEEP` in
>   `tests/test_scanner_adapters.py`, added in wave 5;
> - a base-versus-head differential over all twelve finding-producing parsers,
>   measured in BOTH directions (leaks opened/closed AND legitimate values
>   destroyed/preserved);
> - a mutation check that reads unittest's exit status, not the last output line
>   (a launcher test prints a docker line last, which silently voids a
>   `tail -1 | grep '^OK$'` check).

## Scope answers (doctrine step 1)

- **Target area**: the shared scanner-redaction helpers in
  `kali_pentest_server.py` — `_redact_truncated_secret`, `_redact_scanner_data`,
  `_bounded_for_redaction`, `_clip`, `_clip_finding`, `URL_PORT_TAIL`,
  `SECRET_VALUE_PATTERNS`, and the opener/closer pairs they share. Plus the
  tests that pin them.
- **Mode**: fix-as-we-go. Not report-first, not read-only; working-tree writes
  are in scope.
- **Severity/effort line**: all six confirmed defects are in scope for the fix.
  The issue's own evidence says approaches 1, 4 and 5 are only correct taken
  together, so splitting them is what makes them regress. Anything NEW that this
  run's finder waves surface above "would break a user or a caller" gets fixed
  in a fresh phase; anything below gets filed on GitHub Issues.
- **Delivery**: branch `fix/redaction-hardening` off `b3ca7e1`, commit locally,
  open a PR with `Closes #27`. No push until the user says "push it".

## D1 — how the guard tells its own output from the attacker's (user, 2026-08-28)

**Targeted patches plus a per-call sentinel.** Chosen over restructuring the
pipeline to track redacted spans.

`_redact_truncated_secret` re-scans text that `_redact_scanner_data` already
rewrote, so it cannot distinguish its own `[REDACTED]` placeholder from a
hostile server printing that literal string. Issue #27's approach 3 matched the
placeholder literally and was therefore itself a leak. The ruling:

- `_redact_scanner_data` emits an unguessable per-process sentinel, not
  `[REDACTED]`.
- `_redact_truncated_secret` treats a region opening with that sentinel as
  closed. An attacker cannot forge it.
- The sentinel is materialised to `[REDACTED]` last, at the public boundary.
- H3's terminator set is widened in the same change (the issue: approach 1
  "must be taken together with a widened terminator set").
- H1's closers anchor at the region start rather than searching the region.

The diff stays inside the helpers listed under Target area. The rejected
alternative — redaction returning spans that `_clip` cuts against — was declined
because `_clip` is also called standalone on raw text at three sites, so it
would change call sites across the twelve parsers for a wider blast radius.

## Confirmed list

State values: inherited / confirmed / red-teamed / fixed / filed / declined.
"Inherited" means three prior adversarial rounds confirmed it and this run has
not yet reproduced it from source. Nothing is fixed while still inherited.

| id | site | severity | evidence | state |
|---|---|---|---|---|
| H1 | `kali_pentest_server.py:551` (`closer.search(region)`) | leak | A later unrelated `@` vouches for an orphaned URL credential. `URL_CREDENTIAL` cannot match across a newline but the guard searches the whole region. `https://svc:PWLEAK\nabuse@registrar.tld` keeps `PWLEAK`. A whois record carries an abuse-contact email in nearly every case. | inherited |
| H2 | `kali_pentest_server.py:276` (keyword pattern `[^\r\n]*`) | leak | A keyword line eats a private key's opener, so an unpaired key (no `-----END-----`, which a hostile server omits) leaks in full. `password: -----BEGIN PRIVATE KEY-----\nMIIEv<body>` keeps the body verbatim. Reordering does not fix it: the key pattern needs an END to fire. Same shape for `secret=` before a lowercase key, `authorization:` before a split JWT, `token:` before a split URL credential. | inherited |
| H3 | `kali_pentest_server.py:250` (`URL_PORT_TAIL`) | over-redaction | The port tail accepts only `/ ? #` or end-of-string as a terminator, so a legitimate `https://host:8443` followed by `" ' , ; ) ]`, whitespace or a serialized `\n` loses everything from the URL onward. Every IPv6 URL is truncated: `https://[2001:db8::1]:8443/` → `https://[2001:[REDACTED]`. | inherited |
| H4 | `kali_pentest_server.py:523` + `:618` (guard vs. `\1[REDACTED]`) | over-redaction | A COMPLETE private-key pair destroys the output after it. `_redact_scanner_data` consumes the pair and leaves the opener behind as the `\1` of `\1[REDACTED]`; the orphan guard then matches that surviving opener, finds no closer, and truncates to end-of-value. `-----begin private key-----\nAAA\n-----end private key-----\nName Server: NS1` → `'[REDACTED]'`. The uppercase twin does this on main today. D1's sentinel is the fix. | inherited |
| H5 | `kali_pentest_server.py:557` (`_clip` via the guard's return) | cap violation | **Claim corrected.** Line 557 returns `text[:match.end()] + "[REDACTED]"`, so the result length is `match.end() + 10`, NOT `limit + 10`: overshoot needs the opener to end exactly at the cap. Issue #27's stated input `"A"*8167 + "eyJabcdefgh." + "B"*500` gives 8189, three UNDER the 8192 cap. Reproduced worst case is `"A"*8180 + ...` → 8202, +10. Only the JWT opener can overshoot: PEM uses `keep_opener=False` and cuts before the opener; a URL cut at its colon takes the `continue` at line 553 because `URL_PORT_TAIL.match("")` succeeds on an empty region. Compounds at line 1529, `_clip(body, MAX_EVIDENCE_CHARS - len(cut)) + cut`. | confirmed |
| H6 | `kali_pentest_server.py:549-551` (per-opener locality bound, wave 4) | over-redaction | Two parts, both reproduced. (a) The presence of a second opener alone flips the outcome: `ws://gateway:live and https://docs:9443 contact ops@example.com` → `ws://gateway:[REDACTED]`, while the same string with the second opener removed is untouched — `stop` cuts the region before the closer `ops@`. (b) A JWT's payload segment is itself a valid opener, so `eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKx...` has openers at 0-21 and 21-41: the region for the first is EMPTY and the closer that would have matched at exactly that offset is never given the chance, so a well-formed complete JWT is judged an orphan. | confirmed |
| X1 | `kali_pentest_server.py:545-557` (fixed opener-type order) | **leak** | The loop iterates opener types in the fixed order PEM, URL, JWT and returns on the first orphan of ANY type, so a later PEM orphan preempts an earlier JWT orphan and the JWT payload survives. `eyJhbGciOiJIUzI1NiJ9.LEAKEDPAYLOAD -----BEGIN PRIVATE KEY-----` → `eyJhbGciOiJIUzI1NiJ9.LEAKEDPAYLOAD [REDACTED]`; remove the trailing PEM and the payload is correctly redacted. A hostile server appends a bare `-----BEGIN PRIVATE KEY-----` to disarm the guard for everything before it. The comment at lines 542-544 says "the FIRST orphan wins", which holds within one opener type but not across types. Verified independently by the orchestrator. | confirmed |
| X2 | `kali_pentest_server.py:250` + `:553` | leak (low value) | `URL_PORT_TAIL` accepts an all-numeric password: `https://svc:98765` and `https://svc:12345/inbox` pass through unchanged. 98765 is not even a valid port (>65535), so a port-range check is a cheap discriminator. **Interacts with H3**: widening the terminator set makes X2 strictly worse, so the two must be fixed in one change. Verified independently by the orchestrator. | confirmed |
| X3 | `kali_pentest_server.py:619` + `:557` | over-redaction | H4's mechanism is not PEM-only. `\1[REDACTED]` preserves the opener for the complete URL-credential and complete-JWT patterns too, the guard rematches it, and line 557 truncates the rest of the field. `https://dbadmin:hunter2@db.internal/x` → `https://dbadmin:[REDACTED]`; a complete JWT followed by `Name Server: NS1` loses the name server. Same class as H4; folded into H4's fix, not a separate phase. | confirmed |
| X4 | `kali_pentest_server.py:600` + docstring at `:584-586` | latent | `_bounded_for_redaction` gates the orphan guard on `len(value) > MAX_REDACT_CHARS`, so for any string under 8192 chars `_safe_scanner_value` is `_redact_scanner_data` alone and applies NO guard — yet its docstring calls it "the one correct way to make scanner-controlled data safe to keep". Every current call site routes through `_clip`/`_clip_finding`, so there is no live leak. Any future caller trusting the docstring inherits H1's and H6's orphans directly. Verified independently by the orchestrator. | confirmed |
| X5 | `kali_pentest_server.py:561-572` + `:600` | leak | H1 propagating through the recursive path into a real nuclei field: `_clip_finding(_safe_scanner_value({"extracted-results": ["https://svc:PWLEAK\nabuse@registrar.tld", "ok"]}))` returns the credential intact. Same class as H1; folded into H1's fix. | confirmed |

Source correction that changes how every fix must be tested (observed by the
reproduction wave, verified by the orchestrator): **`_safe_scanner_value` does
not apply the orphan guard to ordinary-length strings.** `_bounded_for_redaction`
(line 600) gates the guard on `len(value) > MAX_REDACT_CHARS`. The guard reaches
short values only through `_clip` / `_clip_finding`. So every reproduction and
every test must exercise the COMPOSED path — `_clip(_safe_scanner_value(x), cap)`
— not `_safe_scanner_value` alone, which is what the parsers actually emit.

## Process lesson this run must not repeat

A fully green 157-test suite hid every over-redaction regression, because every
redaction test asserted only that a secret was ABSENT, never that legitimate
content SURVIVED. Both halves are asserted from now on.
