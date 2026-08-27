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

## Why NOT put this in `validate_target` or the dash guard

These two tools are intentionally exempt from the leading-dash guard
(`guard_target=False`) because a leading `-` is msfconsole's own search syntax.
That exemption is correct FOR A LEADING DASH and must stay. `;` is not search
syntax; it is a command separator. The fix is orthogonal to the dash guard and
must not touch it.

## Fix

Add `_reject_msf_command_chars(value, noun)`: reject a value containing `;`,
`\n`, or `\r` before it reaches the `-x` string. Apply in both tools after the
empty-check. The leading dash stays allowed.

**Reject-list, not allowlist, deliberately.** The command boundary in an `-x`
string is `;` (and a newline in resource-file contexts). A legitimate search
(`type:exploit platform:windows cve:2021-44228 eternalblue`) and a module path
(`exploit/windows/smb/ms17_010_eternalblue`) never contain those three
characters, so a reject-list closes the injection with zero false rejects. An
allowlist (`[A-Za-z0-9 :/_.,*-]`) is more paranoid but would reject legitimate
free-text terms (an apostrophe in an author name, parentheses), trading a real
usability cost for no security gain over blocking the separator. If a future
finding shows another msfconsole separator, add it to the reject set.

## Acceptance

- `metasploit_search("x; irb -e 'puts 1'")` and any `;`/newline-bearing input
  return `❌ Error` and spawn nothing; same for `metasploit_info`.
- A legitimate search (`type:exploit cve:2021-44228`) and a legitimate module
  path still reach msfconsole unchanged.
- A leading-dash input (`-x type:exploit`) still reaches msfconsole — the
  documented exemption is intact.

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
