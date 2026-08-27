# Argument-injection guard centralization (#50, #42, #52)

Anchor for a security cluster: three issues, one root cause — untrusted input
reaching a tool's argv as an option token (CWE-88).

## Anchor — the user's decisions, before wave 1

- **D1 — scope.** "#50 + #42 + #52 together." One branch, one PR.
- **D2 — hydra wordlist.** "Error on empty or missing." An empty or
  non-existent `password_list` returns `❌ Error`; hydra never silently
  substitutes a default wordlist. This CHANGES the calling contract: a bare
  `hydra_attack` call that used to run a rockyou brute force now errors.

## The root cause

The leading-dash rejection that stops a target being read as an option is
written THREE times (`_run_with_capture` guard_target, `_validate_registry_reference`,
`sslscan_scan` inline) but is NOT in `validate_target`, which every tool calls.
So protection depends on which execution path a tool happens to use.

## The trap that makes #50's own suggested fix wrong

#50 suggests putting the rejection inside `validate_target`. That would regress
a DELIBERATE prior decision: `metasploit_search` calls `validate_target(query)`
and is exempted from the dash guard via `guard_target=False`, because a leading
dash in an msfconsole search is msfconsole's OWN search syntax, not a process
option (recorded in wave 5). Putting the guard in `validate_target` breaks that.

**Resolution:** a dedicated `reject_option_like(value)` helper the unguarded
tools call explicitly. `validate_target` stays as-is; the msfconsole exemption
stays intact by simply not calling the new helper.

## Fixes

### F1 (#50, #42) — centralize the leading-dash guard

Add `reject_option_like(value) -> bool` (or a small validating wrapper). Apply
it in the six tools that call `run_command` with a positional target unguarded:
`enum4linux_scan`, `crackmapexec_scan`, `hydra_attack`, `john_crack`,
`hashcat_crack`, `searchsploit_search` — plus `wfuzz_scan` (#42), whose target
reaches wfuzz as a bare positional through `run_command`, not `_run_with_capture`.

Each returns `❌ Error: target must not begin with '-'` (the exact string the
other guards already use) before building argv.

**Out of scope:** the three existing guard sites are NOT collapsed into the new
helper in this PR — that is a wider refactor touching `_run_with_capture` and
`_validate_registry_reference`, both of which other waves depend on. This PR
only ADDS coverage where there is none. `validate_target` is unchanged, so the
`metasploit_search` exemption is untouched.

**Acceptance:** each of the seven tools returns the dash error for a
`-`-leading target and spawns nothing; a normal target still builds argv and
runs; `metasploit_search("-x foo")` still reaches msfconsole (exemption intact).

### F2 (#52A) — hydra `service` allowlist

`hydra_attack`'s `service` is placed as a positional arg with no allowlist, so
`service="-U"` is parsed by hydra as an option. Whitelist it against the
documented set the docstring already names (ssh, ftp, http-get, http-post,
rdp, smb), exactly as `crackmapexec_scan` whitelists its `proto`. An
unrecognized service is rejected with `❌ Error`, not silently coerced — coercing
a typo'd service to ssh would attack the wrong port.

**Acceptance:** each documented service builds argv with that service; a
`-`-leading or unknown service returns `❌ Error` and spawns nothing.

### F3 (#52B, per D2) — hydra wordlist must be explicit and present

Replace the silent rockyou/dirb substitution. An empty `password_list`, or a
provided path that does not exist, returns `❌ Error`. No default wordlist, no
silent downgrade.

**Acceptance:** empty `password_list` errors; a non-existent path errors and
names nothing it silently swapped to; an existing path builds argv with `-P
<that path>`.

## Invariants

1. Argument lists only, never `shell=True`.
2. Every tool stays `@mcp.tool()` async returning `str`, one-line docstring.
3. `tests/fixtures/legacy_tool_contract.json` must not change — signatures are
   unchanged (behaviour inside functions only).
4. No new dependency; nothing needing raw sockets or root.

## Test seam

New file `tests/test_argv_injection.py`. Patch at the `run_command` /
`execute_command` seam; never spawn a binary. Assert on built argv and on the
error strings.
