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

## D1 superseded (user, 2026-08-28): "go with that"

The sentinel described above was **not built**, and the user ruled that closed.
Fixing H4/X3 removes the secret's own opener from redaction's output, so there is
no leftover opener for the guard to rematch and the question the sentinel
answered does not arise. The Spec review axis independently checked this against
the code and found no path where the guard can be fooled by attacker-supplied
`[REDACTED]`. The D1 section above is left exactly as written; this supersedes it.

## D2 — how far an orphan cut reaches (user, 2026-08-28): "Bound the cut at whitespace"

This SUPERSEDES a decision recorded in `docs/specs/2026-08-26-combined-report.md`:

> An orphan-guard redaction truncates to end-of-value BY DESIGN -- once a
> secret's closing anchor is gone there is no way to know where the secret
> ends, so everything after the opener goes.

That premise holds for a private key, whose body legitimately spans lines. It is
false for a URL credential and a JWT: neither can contain whitespace by its own
grammar, so an orphan of either provably ends at the next whitespace. Holding to
the old rule destroyed the rest of the field for any text merely shaped like
`scheme://word:word` — `ws://gateway:live contact ops@example.com` lost the
whole line, and so did the abuse address below the very whois orphan that made
H1 reachable.

The ruling: an anchored (URL or JWT) orphan is redacted only to the end of the
non-whitespace run that follows it. PEM keeps end-of-value. An EMPTY run means
the truncation landed on the opener itself, so the extent is unknown again and
end-of-value still applies there.

Two consequences, both recorded rather than absorbed:

- The corpus keep expectation removed under the earlier ruling is RESTORED. It
  is satisfiable now, and honestly: the email below an orphan survives because
  the cut is bounded, not because the password leaked.
- "The first orphan wins" stopped being true. It was only ever true because
  nothing after an unbounded cut survived. Bounding the cut left a SECOND orphan
  further along in the clear — caught by the differential's own sweep once it was
  taught to measure both directions, in `_parse_whatweb_json`, where the parser
  stringifies a dict and two copies of one credential land in one value. The
  guard now redacts every orphan span rather than the earliest.

## D3 — which URL standard the sanitiser assumes (user, 2026-08-28): "Assume WHATWG, close the leak"

D2 was argued on the premise that a URL credential and a JWT "cannot contain
whitespace by their own grammar". **That premise is wrong for URLs**, and the red
team broke it. Two reviewers disagreed, each correct about a different standard:

- RFC 3986 says userinfo cannot contain whitespace, which makes the bounded cut
  sound. The Spec axis relied on this and passed D2.
- The WHATWG URL Standard says a parser REMOVES tab, CR and LF from the input
  before parsing. So `https://user:PASS\nWORD@host/x` is the single credential
  `user:PASSWORD`, and bounding the cut at the newline left `WORD` in the report.

The user ruled for WHATWG, so the sanitiser now assumes the more permissive
parser. A URL orphan's run ends at a SPACE rather than at any whitespace, and
only where no `@` is still reachable before that space; an `@` ahead of it means
the credential may be continuing across a character the parser will strip. A JWT
keeps the whitespace bound, its compact serialization admitting none.

**This costs the benefit D2 was chosen for.** The whois abuse address on the line
below an orphaned credential cannot survive, because under a WHATWG parser it may
itself be part of that credential. Its keep expectation is removed from the paired
table for the second time, and this is the reason. Both halves of the earlier
claim — that the keep was satisfiable "honestly, because the cut is bounded" —
were true under D2 and are not true under D3.

D2's other benefit stands and is what the ruling preserved:
`ws://gateway:live contact ops@example.com` keeps its tail, no `@` being
reachable before the space.

## Confirmed list

State values: inherited / confirmed / red-teamed / fixed / filed / declined.
"Inherited" means three prior adversarial rounds confirmed it and this run has
not yet reproduced it from source. Nothing is fixed while still inherited.

| id | site | severity | evidence | state |
|---|---|---|---|---|
| H1 | `kali_pentest_server.py:551` (`closer.search(region)`) | leak | A later unrelated `@` vouches for an orphaned URL credential. `URL_CREDENTIAL` cannot match across a newline but the guard searches the whole region. `https://svc:PWLEAK\nabuse@registrar.tld` keeps `PWLEAK`. A whois record carries an abuse-contact email in nearly every case. | fixed |
| H2 | `kali_pentest_server.py:276` (keyword pattern `[^\r\n]*`) | leak | A keyword line eats a private key's opener, so an unpaired key (no `-----END-----`, which a hostile server omits) leaks in full. `password: -----BEGIN PRIVATE KEY-----\nMIIEv<body>` keeps the body verbatim. Reordering does not fix it: the key pattern needs an END to fire. Same shape for `secret=` before a lowercase key, `authorization:` before a split JWT, `token:` before a split URL credential. | fixed |
| H3 | `kali_pentest_server.py:250` (`URL_PORT_TAIL`) | over-redaction | The port tail accepts only `/ ? #` or end-of-string as a terminator, so a legitimate `https://host:8443` followed by `" ' , ; ) ]`, whitespace or a serialized `\n` loses everything from the URL onward. Every IPv6 URL is truncated: `https://[2001:db8::1]:8443/` → `https://[2001:[REDACTED]`. | fixed |
| H4 | `kali_pentest_server.py:523` + `:618` (guard vs. `\1[REDACTED]`) | over-redaction | A COMPLETE private-key pair destroys the output after it. `_redact_scanner_data` consumes the pair and leaves the opener behind as the `\1` of `\1[REDACTED]`; the orphan guard then matches that surviving opener, finds no closer, and truncates to end-of-value. `-----begin private key-----\nAAA\n-----end private key-----\nName Server: NS1` → `'[REDACTED]'`. The uppercase twin does this on main today. D1's sentinel is the fix. | fixed |
| H5 | `kali_pentest_server.py:557` (`_clip` via the guard's return) | cap violation | **Claim corrected.** Line 557 returns `text[:match.end()] + "[REDACTED]"`, so the result length is `match.end() + 10`, NOT `limit + 10`: overshoot needs the opener to end exactly at the cap. Issue #27's stated input `"A"*8167 + "eyJabcdefgh." + "B"*500` gives 8189, three UNDER the 8192 cap. Reproduced worst case is `"A"*8180 + ...` → 8202, +10. Only the JWT opener can overshoot: PEM uses `keep_opener=False` and cuts before the opener; a URL cut at its colon takes the `continue` at line 553 because `URL_PORT_TAIL.match("")` succeeds on an empty region. Compounds at line 1529, `_clip(body, MAX_EVIDENCE_CHARS - len(cut)) + cut`. | fixed |
| H6 | `kali_pentest_server.py:549-551` (per-opener locality bound, wave 4) | over-redaction | Two parts, both reproduced. (a) The presence of a second opener alone flips the outcome: `ws://gateway:live and https://docs:9443 contact ops@example.com` → `ws://gateway:[REDACTED]`, while the same string with the second opener removed is untouched — `stop` cuts the region before the closer `ops@`. (b) A JWT's payload segment is itself a valid opener, so `eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKx...` has openers at 0-21 and 21-41: the region for the first is EMPTY and the closer that would have matched at exactly that offset is never given the chance, so a well-formed complete JWT is judged an orphan. | fixed |
| X1 | `kali_pentest_server.py:545-557` (fixed opener-type order) | **leak** | The loop iterates opener types in the fixed order PEM, URL, JWT and returns on the first orphan of ANY type, so a later PEM orphan preempts an earlier JWT orphan and the JWT payload survives. `eyJhbGciOiJIUzI1NiJ9.LEAKEDPAYLOAD -----BEGIN PRIVATE KEY-----` → `eyJhbGciOiJIUzI1NiJ9.LEAKEDPAYLOAD [REDACTED]`; remove the trailing PEM and the payload is correctly redacted. A hostile server appends a bare `-----BEGIN PRIVATE KEY-----` to disarm the guard for everything before it. The comment at lines 542-544 says "the FIRST orphan wins", which holds within one opener type but not across types. Verified independently by the orchestrator. | fixed |
| X2 | `kali_pentest_server.py:250` + `:553` | leak (low value) | `URL_PORT_TAIL` accepts an all-numeric password: `https://svc:98765` and `https://svc:12345/inbox` pass through unchanged. 98765 is not even a valid port (>65535), so a port-range check is a cheap discriminator. **Interacts with H3**: widening the terminator set makes X2 strictly worse, so the two must be fixed in one change. Verified independently by the orchestrator. | fixed |
| X3 | `kali_pentest_server.py:619` + `:557` | over-redaction | H4's mechanism is not PEM-only. `\1[REDACTED]` preserves the opener for the complete URL-credential and complete-JWT patterns too, the guard rematches it, and line 557 truncates the rest of the field. `https://dbadmin:hunter2@db.internal/x` → `https://dbadmin:[REDACTED]`; a complete JWT followed by `Name Server: NS1` loses the name server. Same class as H4; folded into H4's fix, not a separate phase. | fixed |
| X4a | `kali_pentest_server.py:600` + docstring at `:584-586` | latent | **Same defect as the X4 row below; the two states disagreed and this is the stale one.** `_bounded_for_redaction` gates the orphan guard on `len(value) > MAX_REDACT_CHARS`, so for any string under 8192 chars `_safe_scanner_value` is `_redact_scanner_data` alone and applies NO guard — yet its docstring calls it "the one correct way to make scanner-controlled data safe to keep". Every current call site routes through `_clip`/`_clip_finding`, so there is no live leak. Any future caller trusting the docstring inherits H1's and H6's orphans directly. Verified independently by the orchestrator. | fixed |
| X5 | `kali_pentest_server.py:561-572` + `:600` | leak | H1 propagating through the recursive path into a real nuclei field: `_clip_finding(_safe_scanner_value({"extracted-results": ["https://svc:PWLEAK\nabuse@registrar.tld", "ok"]}))` returns the credential intact. Same class as H1; folded into H1's fix. | fixed |

| C1 | `kali_pentest_server.py` keyword pattern lookahead | **leak, introduced by the first attempt at this fix** | The H2 lookahead stopped the keyword value at ANY bare `scheme://`, not at a URL-CREDENTIAL opener, so a keyword whose value is an ordinary URL stopped being redacted at all. `password: http://svc.example/cb?k=SECRETVAL1` — base `password: [REDACTED]`, first-attempt head kept the whole URL. The guard cannot save it: there is no orphan opener to cut on. Found by the Spec review axis, not by the suite or the corpus. Fixed by stopping at `_URL_CREDENTIAL_OPENER_BODY`. | fixed |
| C2 | `kali_pentest_server.py` `_URL_CREDENTIAL_OPENER` host class | **leak, introduced by the first attempt at this fix** | The `[`/`]` exclusion added for H3's IPv6 case removed brackets from the WHOLE userinfo rather than just the leading position, so any credential containing a bracket escaped both `URL_CREDENTIAL` and the guard. `https://us[er:PASSWORD1@host.example/x` — base redacted, first-attempt head leaked. Fixed by excluding a bracket only in the first character, which is the only position that means an IPv6 literal. | fixed |
| X4 | `kali_pentest_server.py` `_safe_scanner_value` docstring | latent | Closed by correcting the docstring, which is the disposition this spec named. It no longer claims to be "the one correct way to make scanner-controlled data safe to keep"; it now states that it does NOT guard anything under `MAX_REDACT_CHARS` and that every caller must slice through `_clip`/`_clip_finding`. | fixed |

**C1 and C2 are the reason the sweep exists.** Both were introduced by the fix
itself, both were invisible to a 274-test suite and to a 29-sample differential
that reported zero regressions, and both belong to one class: a change that makes
a pattern match LESS than base. A fixed corpus can only catch a regression in a
shape its author already imagined. `tests/redaction_differential.py` therefore now
carries `sweep`, which walks the product of keyword prefix, secret body and
trailing text — 512 combinations — through the composed public path and fails on
any token the base removed and head leaves behind. On the first attempt it fires
on 56 of them; on the current revision, 0.

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


## Round 5 review findings, all fixed

| id | source | severity | what | state |
|---|---|---|---|---|
| F1 | Spec axis | over-redaction | H6(a) was marked fixed but had regressed into over-redacting BOTH sides: `ws://gateway:live contact ops@example.com` lost everything from the URL on, where base kept it. Fixed by D2. | fixed |
| F2 | Spec axis | wrong claim | The H5 correction was itself wrong. Measured on base AND head, the URL opener overshoots too (`"A"*8171 + "https://svc:BBBB"` → 8193 against an 8192 cap). The claim survived in the `_clip` comment, the spec row and the test docstring, and the test exercised only JWT pads, so the URL case sat unpinned while reading as verified. Both openers are now covered, across a 22-offset range. | fixed |
| F3 | Spec axis | gate gap | The sweep measured leaks only, so the one class that regressed — destruction — was invisible to it. It now measures both directions. | fixed |
| R1 | red team | **leak** | `password: https://svc:12345` survived in full: the keyword lookahead stopped at the opener, then the port branch accepted the numeric value as a port, though the keyword had already said it was a password. The value now stops at an opener ONLY where that opener ends the line, which is the one case whose body outlives the value. | fixed |
| R2 | red team | **leak** | `https://:PASSWORD1@db.internal/x` bypassed every matcher, because the userinfo was required to have a first character. An empty username is a real credential shape. Pre-existing on base as well as head. | fixed |
| R3 | red team | cap violation | `_clip` with a limit shorter than the placeholder made the slice negative and GREW the result: `_clip("eyJabcde.", 9)` returned 28 characters. Latent under shipped caps, but the invariant is that it never exceeds its limit. | fixed |
| R4 | red team | disclosure | The orphan branch kept `scheme://user:` while the complete-pattern branch already dropped the userinfo, so the username leaked out of one path and not the other. The orphan branch now keeps the scheme alone. | fixed |
| S1r | Standards | gate gap | The gate ran only when a human remembered; CI ran `unittest discover` alone. It now has its own workflow step, with full history, since it diffs against a base revision. | fixed |
| S2r | Standards | drift risk | Two spellings still duplicated: the userinfo tail and the PEM END. Both are single constants now. | fixed |
| S5r | Standards | gate gap | The terminator set had drifted a THIRD time — the differential's table held 13 of the 15 the pattern accepts, missing `}` and the real newline. Hand-syncing three copies is what kept failing, so the pattern is now the one spelling, the differential derives its samples from it, and a test asserts the paired table covers every terminator the pattern accepts. Add one to the pattern and the suite fails until a row pins it. | fixed |
| S1m | Standards | hazard | The `CLAUDE.md` mutation recipe was a five-line chain that overwrote TRACKED source and left the tree dirty if interrupted. It is `scripts/mutation-check <rev>` now, which refuses to start on a dirty tree and restores on any exit. | fixed |
| S4 | Standards | style | Comment density. The blocks narrating what was tried are trimmed to what the code does; the history lives here and in the commit messages. | fixed |
