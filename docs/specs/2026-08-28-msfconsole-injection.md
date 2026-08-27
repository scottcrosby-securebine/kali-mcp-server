# msfconsole command-injection fix (#58)

Anchor for a single security fix: `metasploit_search` and `metasploit_info`
let a caller inject msfconsole commands, up to RCE.

## Anchor — decisions

- **D3 (from the argv-injection session).** #58 is kept SEPARATE from the
  #50/#42/#52 cluster: different mechanism (msfconsole command chaining in the
  `-x` string, not argv option injection), pre-existing, and a behaviour change
  to the metasploit tools that deserves its own review.

## The defect (confirmed, argv observed on the dev host)

Both tools interpolate caller input into a single msfconsole `-x` string:

```python
cmd = ["msfconsole", "-q", "-x", f"search {query_clean}; exit"]   # metasploit_search
cmd = ["msfconsole", "-q", "-x", f"info {module_clean}; exit"]     # metasploit_info
```

`validate_target` only trims and length-bounds. msfconsole splits the `-x`
string on `;`, so the caller supplies further console commands:

```
metasploit_search("x; irb -e 'puts 1'; exit")
  -> argv[-1]: "search x; irb -e 'puts 1'; exit; exit"
```

msfconsole core exposes `irb -e <ruby>` (arbitrary Ruby -> process execution),
`resource <file>`, `spool <file>`, `load`. So a crafted search does far worse
than search. Bounded by the hardened container (non-root, cap-drop, read-only
root, no raw sockets), but it is untrusted-string-controls-console-commands.

## Two vectors, and where the guard belongs

These two tools are exempt from the PROCESS-argv leading-dash guard
(`guard_target=False`) because the value is interpolated into ONE `-x` token, so
a leading dash is not a process option. That exemption is about argv and stays.

But it says nothing about what msfconsole then does with the token, and there
are two injection vectors inside the `-x` string:

1. **Command chaining.** `;` or a newline appends a console command; `irb -e
   <ruby>` is RCE.
2. **Acting options (found by the red team, F1).** A token beginning with `-` is
   a msfconsole SEARCH/INFO OPTION, not a term. `search -o <path>` writes a CSV
   to a caller-named path -- a file write through what looked like a search.
   `metasploit_search("-o /tmp/x.csv eternalblue")` built
   `search -o /tmp/x.csv eternalblue; exit` and passed the first-cut guard.

The original framing of this spec -- "a leading dash is msfconsole's own search
syntax... not an option that acts" -- was WRONG for `-o`. Both vectors are
msfconsole-command-level and are guarded in `_reject_msf_injection`, separate
from the process-argv guard, which is untouched.

## Fix

`_reject_msf_injection(value, noun)`, applied in both tools after the
empty-check, rejects:

- any value containing `;`, `\n`, or `\r` (command chaining);
- any whitespace-delimited token beginning with `-` (an acting option).

**Reject the shape, not a denylist of flags.** For the separators: `;` is the
`-x` command boundary and a legit search never contains it, so a reject-list is
zero-false-reject (newline rejected as defence-in-depth for resource-file
contexts). For the options: the acting flags (`-o` today) are a MOVING denylist,
so reject the option SHAPE instead -- a real query is `key:value` or free text
and never starts a token with `-`, while an internal dash (`cve:2021-44228`,
`apache-struts`) is fine because the token starts with a letter. This closes
`-o` and any future acting flag at once.

**Interaction with wave 5, named rather than silent.** Wave 5 set
`guard_target=False` and a test asserted "msfconsole's own search flags still
work". That observable behaviour is now REVERSED: an option-shaped query is
rejected. The reversal is correct -- those flags were the `-o` hole -- and the
process-argv exemption itself is unchanged; only the msfconsole-content rule is
new. The wave-5 test (`test_leading_dash_guard_applies_only_where_the_target_reaches_argv`)
is updated to assert the option token is rejected by the CONTENT guard, not the
process guard, preserving its structural point.

## Acceptance

- `metasploit_search("x; irb -e 'puts 1'")` and any `;`/newline-bearing input
  return `❌ Error` and spawn nothing; same for `metasploit_info`.
- A legitimate search (`type:exploit cve:2021-44228`) and a legitimate module
  path still reach msfconsole unchanged.
- An option-shaped query (`-o /tmp/x`, `-S`, `-h`) returns `❌ Error` and spawns
  nothing; it is rejected by the content guard, NOT by the process-argv guard
  (`guard_target=False` is intact).
- An internal dash (`cve:2021-44228`, a module path) still reaches msfconsole.

## Invariants

1. Argument lists only, never `shell=True`. (The `-x` value is one argv token;
   this is msfconsole-internal command injection, not shell injection.)
2. Both tools stay `@mcp.tool()` async returning `str`, one-line docstring.
3. `tests/fixtures/legacy_tool_contract.json` must not change (signatures
   unchanged).

## Test seam

New file `tests/test_msfconsole_injection.py`. Patch the run_command /
execute_command seam; never spawn a binary. Assert on the built `-x` string and
the error path.
