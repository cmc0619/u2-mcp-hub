# BASIC tools: design

Date: 2026-10-31. Project 2 of 2. It builds on the admin UI (project 1: phases 1, 2a, 2b and 3, all merged), whose spec reserved the permissions `basic.read`, `basic.write`, `basic.compile` and `basic.catalog`.

## Goal

Let an AI assistant work with the UniVerse and UniData BASIC programs on a connection: list them, read them, search them, save a change, compile, and catalog locally. Each step is under its own per-connection permission, and nothing here can reach a file that is not a BASIC program file.

## Non-goals

- **No "run program" tool.** `call_subroutine` (`subroutine.call`) and `execute_tcl` (`tcl.run`) already cover execution under their own permissions. `execute_tcl` keeps blocking `BASIC`, `CATALOG` and `RUN`; the tools here are the only gated way to compile or catalog.
- **No global or normal (account) catalog.** Only local cataloging is offered. Global cataloging replaces a program for every account on the server, and an admin does it at TCL.
- **No regex search.** Search is a literal substring match (see Decisions).
- **No delete, rename or decatalog.** These are rare, destructive, and still available through TCL to people who hold `tcl.run`.
- **No schema migration and no role changes.** The phase-1 spec already gave the built-in roles their `basic.*` permissions.
- **No "is it catalogued?" in `list_programs`.** It is not cheap to find out; `list_catalog` exists for that.

## Decisions

1. **One module of tools, one module of pure helpers.** The tools are in `src/u2_mcp/tools/basic.py`, registered through `tools/__init__.py`. Names, source conversion, hashing, the command table and the compiler-output parsers are in `src/u2_mcp/utils/basic_source.py`, with no I/O, so they can be tested directly.
2. **Program files are allow-listed by name: `U2_BASIC_FILES`.** It is a comma-separated list of glob patterns, matched without regard to case. The default is `*BP,BP.*`, which covers `BP`, `XBP`, `SUBS.BP` and `BP.UTIL`. Without this list, `read_program("CUSTOMERS", …)` would be `records.read` under another checkbox, and `write_program` would be `records.write`, which breaks the one-tool-one-permission promise the roles page makes. The list is server-wide (`U2Config.basic_files`), so `routing.config_for` carries it into every team-mode connection, and no schema change is needed. File names ending in `.O` (UniVerse object files) are always refused.
3. **Strict names, never quoted.** File and program names must match `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`. The first character is alphanumeric, which rules out the `*`, `-`, `$`, `!` and `_` prefixes that U2 gives meaning to (catalog scope, options, UniData object records). Names are spliced into `BASIC` and `CATALOG` unquoted. With this allowlist there is nothing to quote, which avoids the differences between the two products' quoting rules. Command builders re-check the names, as defence in depth.
4. **`pattern` never reaches TCL.** The tools run `SSELECT <file>` using only the validated file name. They read the whole select list (up to 50,000 ids) and filter it in Python with `fnmatchcase`. Patterns match `[A-Za-z0-9._*-]{1,64}`. When the list is longer than 50,000, they run `CLEARSELECT` so that the unread rest cannot feed the next command on the session.
5. **Object code detection.**
   - UniVerse (`uvcs`): `BP.O` holds the object code. If it opens, its ids are the compiled programs; if it does not, `compiled` is `null`.
   - UniData (`udcs`): the object code is in the same file as `_NAME`. Those ids are hidden from the listing and mark `NAME` as compiled.
6. **Source text and the stored record.**
   - A record's lines are its attributes (split on AM, `chr(254)`). An empty record has no lines.
   - Saving turns `\r\n` and lone `\r` into `\n`, then joins the lines with AM. Nothing is stripped, so a trailing newline becomes an empty last line.
   - Source containing `chr(251)`–`chr(255)` (the text, subvalue, value, attribute and item marks) is refused. In Python these are also the code points of `û ü ý þ ÿ`, so source containing those letters is refused (a known limitation; see Risks). Any of those would silently change the record's shape.
   - Source over 1,000,000 characters is refused.
   - Invariant, tested: a record read with `read_program(numbered=False)` and written back unchanged stores the identical record and reports the same hash.
7. **Optimistic concurrency with a hash.**
   - The hash is the SHA-256 hex digest of the raw stored record (AM-joined, UTF-8 with `surrogatepass`), not of the displayed lines. `read_program` always returns the hash of the whole record, even when it returns only some of the lines.
   - `write_program` with no `expected_hash` creates a new program only: it refuses if the program exists.
   - With `expected_hash`, the stored record must exist and hash to that value; otherwise it refuses and says to read again. It does not return the current hash, so a caller cannot overwrite without reading.
   - The check and the write are one atomic step. `write_program` reads the record under a non-waiting U2 record lock (`READU`), compares the hash, writes, and releases the lock in a `finally`. A lock belongs to the session, so saves made on one connection are also serialized by a per-session guard. A program locked by another user is refused with `<PROGRAM> is locked by another user; try again later`.
8. **`confirm=True` on every change.** `write_program`, `compile_program` and `catalog_program` take `confirm: bool = False` and return `confirmation_required` until it is set, as every existing write tool does.
9. **Read-only is enforced twice.** In team mode, `access.decide` refuses `basic.write`, `basic.compile` and `basic.catalog` on a read-only connection and under `U2_READ_ONLY`, because they are in `WRITE_PERMISSIONS`. In local mode there is no store, and the guard does not decide. So each change tool also checks `manager.config.read_only` first, as `write_record` does. `basic.read` is not a write, and works on read-only connections.
10. **The operator's blocklist wins.** If `U2_BLOCKED_COMMANDS` names `BASIC`, `compile_program` refuses; if it names `CATALOG`, `catalog_program` refuses. Both verbs are always in the built-in `ESCAPE_COMMANDS`, which still governs `execute_tcl`, so the check here is against the operator's own list (`config.blocked_commands`) only.
11. **One command table, keyed on `config.service`.** Both products take `BASIC <file> <program>` and `CATALOG <file> <program> LOCAL`. The mode keyword is always given, because UniData catalogs globally when none is given. The table is still keyed by service, so a product-specific difference found during manual acceptance changes one line.
12. **Compile results are never guessed.**
    - `status` is `failed` when a failure marker is present (UniVerse `Errors detected` or `No Object Code`; UniData `compilation failed` or `syntax error`).
    - It is `compiled` only when the success marker is present (UniVerse `Compilation Complete`; UniData `compilation finished`) and no errors were parsed.
    - Anything else is `unknown`.
    - The raw output is always returned, capped at 20,000 characters. Errors are parsed best-effort into `{line, message}` and capped at 200.
    - The marker strings and output shapes come from the products' documented formats. They are listed for checking under manual acceptance.
13. **Catalog output is not interpreted.** `catalog_program` returns `status: "ran"` with the output. Catalog messages differ between releases, so the caller reads them.
14. **Search is literal and bounded.** It is a substring match, case-insensitive by default, with no regex. Sync tools run inline on the request task, so a catastrophic regex would stall the server.
    - `text`: 1–200 characters.
    - Programs scanned: at most `max_programs` (default 200, ceiling 1,000).
    - Matches: at most `max_matches` (default 100, ceiling 1,000).
    - Characters read: at most 20,000,000 in total.
    - Each matched line is trimmed to 300 characters.
    - The result says which bound stopped it.
15. **Audit never stores source text.** `utils.audit.summarize_parameters` replaces a string `source` parameter with `{"chars", "lines", "sha256"}`. The `sha256` is the hash the record will have once saved. The server's audit wrapper calls it once, before both sinks (the JSONL log and the settings database). Results are logged as before: `read_program`'s result holds source only when `U2_AUDIT_INCLUDE_RESULTS` is on, truncated as today.
16. **Roles: no change.** This matches spec lines 129–130 and the existing tests:
    - Viewer and Analyst: no `basic.*`. BP records stay reachable as data through `records.read`, as they are today.
    - Developer: `basic.read`, `basic.write` and `basic.compile`.
    - Owner adds `basic.catalog`.
    - `Imported access` keeps excluding every `basic.*` permission, so grants nobody chose do not gain compile rights.
    - No new role is added; Developer already exists.
17. **The admin roles page needs no new labels.** It lists each permission's tools from `TOOL_PERMISSIONS`, so mapping the six tools fills the four `basic.*` rows. The dead fallback "Reserved for BASIC tools" becomes "No tools".
18. **Parameter names follow the existing tools:** `file_name`, `program` (the record id), and `connection` last.

## Tools

Every tool takes `connection: str | None = None` and returns a dict. A refusal is `{"error": <message>, ...}`.

| Tool | Permission | Signature |
|------|-----------|-----------|
| `list_programs` | `basic.read` | `(file_name="BP", pattern="*", max_results=500, connection=None)` |
| `read_program` | `basic.read` | `(file_name, program, start_line=1, max_lines=2000, numbered=True, connection=None)` |
| `search_programs` | `basic.read` | `(file_name, text, pattern="*", case_sensitive=False, max_programs=200, max_matches=100, connection=None)` |
| `write_program` | `basic.write` | `(file_name, program, source, expected_hash=None, confirm=False, connection=None)` |
| `compile_program` | `basic.compile` | `(file_name, program, confirm=False, connection=None)` |
| `catalog_program` | `basic.catalog` | `(file_name, program, confirm=False, connection=None)` |

Return shapes:

- `list_programs`: `{file_name, programs: [{name, compiled: bool|null}], count, total_matching, truncated, warning?}`. `max_results` is capped at 5,000.
- `read_program`: `{file_name, program, hash, line_count, start_line, end_line, truncated, next_start_line?, numbered_source | source}`. `numbered_source` puts each line as `f"{n:>5}  {text}"`. `source` (when `numbered=False`) is the exact lines, joined with `\n`. `max_lines` is capped at 5,000.
- `search_programs`: `{file_name, text, matches: [{program, line, text}], match_count, programs_scanned, programs_matching_pattern, unreadable, truncated, stopped_because: null|"max_matches"|"max_programs"|"max_bytes"}`.
- `write_program`: `{status: "saved", created: bool, file_name, program, hash, line_count}`, or `{status: "confirmation_required", ...}`.
- `compile_program`: `{file_name, program, command, status: "compiled"|"failed"|"unknown", errors: [{line: int|null, message}], warnings: [str], output, output_truncated}`.
- `catalog_program`: `{file_name, program, command, status: "ran", output, output_truncated}`.

Error messages (exact):

- `BASIC changes are disabled in read-only mode`
- `<kind> must be 1-64 letters, digits, '.', '_' or '-', starting with a letter or digit` (kind is `file_name` or `program`)
- `<FILE> holds object code, not source`
- `<FILE> is not a BASIC program file on this server. Program files are those matching U2_BASIC_FILES: <patterns>`
- `pattern may contain only letters, digits, '.', '_', '-' and '*'`
- `<PROGRAM> not found in <FILE>`
- `<PROGRAM> already exists in <FILE>; read it with read_program and pass its hash as expected_hash`
- `<PROGRAM> changed since you read it; read it again with read_program`
- `<PROGRAM> no longer exists in <FILE>; leave expected_hash out to create it`
- `<PROGRAM> is locked by another user; try again later`
- `source is longer than 1000000 characters`
- `source line <n> contains a U2 mark character (chr 251-255), which would change the record's shape`
- `text must be 1-200 characters`
- `<VERB> is in U2_BLOCKED_COMMANDS on this server, so this tool is turned off`

In team mode, a refusal from the guard is unchanged, for example `you need basic.read on Prod; ask an admin` and `Prod is read-only`.

## Permissions

`TOOL_PERMISSIONS` gains six entries, one per tool, as listed above. `PERMISSIONS`, `WRITE_PERMISSIONS` and `BUILTIN_ROLES` are unchanged. `check_tool_coverage` and the existing permission tests stay green.

## Safety summary

- The file allowlist (`U2_BASIC_FILES`) and the name allowlist are checked before any I/O.
- No caller text reaches TCL except validated names, and patterns are applied in Python.
- Changes need `confirm=True`, are refused in read-only mode (twice; see Decision 9), and respect the operator's blocklist.
- Every command uses `execute_command`, so `U2_QUERY_TIMEOUT` applies. A compile or catalog that outruns it is abandoned: the session is closed and the next call reconnects, as for any query. The docs say so.
- Outputs are capped (Decisions 12 and 14, and the read and list caps above).
- Audit logs a summary of the source, never the text.

## Testing

- **Unit tests** of `basic_source`: names, the file allowlist, source↔record round trips, hashing, the mark refusal, both compile parsers (success, errors and unknown, for each product), and the command builders refusing bad names.
- **Mock extension.** `MockSession.select_from_files` is an opt-in flag, off by default, so existing tests do not change. When it is on, a bare `SELECT <file>` or `SSELECT <file>` on a seeded file sets the select list to that file's sorted keys. A session helper, `add_program_file`, seeds a file and turns the flag on. `sim_driver.py` is unchanged; no browser test needs BASIC.
- **Tool tests** (local mode, `connection_manager` fixture), for every tool:
  - success on UniVerse, and on UniData through a `udcs` config;
  - each refusal;
  - read-only refusal for the three change tools (`mock_config_read_only`);
  - the read-then-write round-trip invariant;
  - stale hash and create-only behaviour;
  - compile success, failure and unknown output on both products;
  - the blocklist refusal.
- **Team-mode permission tests**, with a `team`-style fixture:
  - Viewer is refused each `basic.read` tool;
  - Developer can read, write and compile but is refused catalog;
  - Owner can catalog;
  - the change tools are refused on a read-only connection and under the global `U2_READ_ONLY` (`install_store(..., global_read_only=True)`), while reading still works there.
- **One end-to-end journey** in `tests/test_team_mode_e2e.py`, over real HTTP:
  - Viewer is refused `read_program`;
  - the admin changes the grant to Developer (`store.update_grant`), and `read_program` returns the source;
  - `write_program` saves the program, and its audit row holds `{chars, lines, sha256}`, not the text.
- **Manual acceptance** against real U2, added to `docs/admin.md` §8: the compile output on both products (success and an error), the `CATALOG … LOCAL` output, object detection with `BP.O` and with `_NAME`, and the `CLEARSELECT` behaviour.

## Risks

- **The compile and catalog output shapes are from documentation, not from a live server.** The tools return raw output every time and report `unknown` rather than guess, and manual acceptance checks the markers.
- **A CATALOG that prompts** (for example over an existing entry) waits until the query timeout, which then drops the session. This is documented, and checked during manual acceptance.
- **The record lock's error code on UniData is unverified.** The lock is a `READU` that does not wait; uopy reports a conflict as status 30002. If UniData reports another code, the save still does not happen, and the caller sees uopy's own message instead of the friendly one. Checked during manual acceptance.
- **NLS accounts.** On an account without NLS, `û ü ý þ ÿ` are the marks and cannot be in a record anyway. How uopy represents marks on an NLS or Unicode-enabled account is unverified. If it maps `ü` to U+00FC, `write_program` refuses ordinary German, Nordic or French source that contains those letters. This is checked during manual acceptance, and the rule changes if needed.
- **The `U2_BASIC_FILES` default can miss a site's naming** (for example `PROGRAMS`). The refusal message names the variable and its patterns, so the fix is obvious.
