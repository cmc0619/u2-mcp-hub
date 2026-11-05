# Security and reliability

u2-mcp is meant to be safe to point at a production MultiValue database. This
document records the security and reliability behaviour that makes that
possible: the identity, attribution and durability guarantees an operator needs
before letting an AI assistant near real business data.

It is organised as a log of findings: what was wrong, how it was found, and the
test that now guards against it. It is a working record, updated as the work
proceeds, not a summary written afterwards. Some mechanisms named in older
findings (the SSE transport, environment-configured OAuth, the credential map, the
connection health checker and the JSONL audit file) were later removed; where that
changed a finding, the finding says what replaced it.

## Method

Three rules govern the work.

**Find defects with tests, not with reading.** Every fix starts as a test that
fails against the unfixed code. That test is the specification of the defect, and
later the proof it is gone.

**Every claim has a test.** Each finding below names the tests that assert the
behaviour it describes, and CI runs them on every change.

**Change behaviour, not architecture.** Fixes stay inside the existing
structure of the server rather than becoming a rewrite.

## Finding 0 — the test doubles had drifted from the code

`tests/test_tools/` was empty, and the reason turned out to be structural rather
than a matter of effort. The mock `uopy` layer modelled an API the server no
longer calls:

| The mocks provided | The code actually calls |
| --- | --- |
| `session.open(name)` | `uopy.File(name, session=...)` |
| `session.command()` then `cmd.exec()` | `uopy.Command(text, session=...)` then `cmd.run()` |
| `session.transaction_start()` | `session.tx_start()` |
| `session.disconnect()` | `session.close()` |

Any test written against those doubles would have exercised a fiction. Rebuilding
them against the real `uopy` 1.4 surface was therefore the first change, and it
immediately surfaced Finding 2 below — a defect that reading the code had not
revealed.

## Finding 1 — non-ASCII business data was silently deleted

**Where:** `ConnectionManager._sanitize_output()`

**What happened:** after converting MultiValue delimiters to readable separators,
the sanitizer kept only characters in the range 32–126. Every other character was
dropped without comment.

**What it cost:** `MÜLLER GmbH` was returned as `MLLER GmbH`. `£1,250.00` was
returned as `1,250.00`. No error, no warning, no indication that the answer had
been altered — which makes it worse than a failure, because an operator cannot
tell a corrupted result from a correct one. For any distributor with European or
Latin American trading partners this corrupts names, addresses and amounts.

**The fix:** filter by Unicode category instead of by code point. Newlines and
tabs are kept, the control, format, surrogate, private-use and unassigned
categories are dropped, and every ordinary printable character survives whatever
alphabet it belongs to. Terminal control codes are still stripped.

**Proof:** `tests/test_connection.py::TestOutputSanitization` — accented names,
currency symbols, delimiter conversion and control-code removal are each asserted
separately.

## Finding 2 — auto-reconnect never reconnected

**Where:** `ConnectionManager.get_session()`

**What happened:** on detecting a dead session the method set `self._session` to
`None`, cleared the file cache, and called `connect()`. But `connect()` begins by
returning early if a connection record for that name exists and is still marked
active — and nothing had cleared that record. So no reconnect occurred, and
`get_session()` returned `None` to its caller.

**What it cost:** every request after a dropped connection failed with
`AttributeError: 'NoneType' object has no attribute ...`, and kept failing. A
single network blip left the server permanently broken until someone restarted
it.

**The fix:** a `_discard_connection()` helper drops the session, the file cache,
the connection record and any transaction state before reconnecting, so the
subsequent `connect()` genuinely opens a new session. `get_session()` now raises a
`ConnectionError` rather than returning `None` if a session still cannot be
established.

**Proof:**
`tests/test_connection.py::TestConnectionLifecycle::test_get_session_reconnects_when_session_went_inactive`

## Finding 3 — a truncated answer was presented as a complete one

**Where:** `tools/query.py::execute_query` and `::get_select_list`

**What happened:** `execute_query` appended `SAMPLE <n>` to any `LIST` that did not
already have one, capping results at `U2_MAX_RECORDS`. The response said which
limit had been applied, but nothing marked the answer as partial — and an AI
client reading that response has no reason to treat it as incomplete.

**What it cost:** "list the open invoices over $1,000" could return the first
hundred and read exactly like all of them. `get_select_list` had the same shape:
it set a `truncated` flag but offered nothing an operator would notice. A wrong
answer that looks right is the failure mode that actually harms a business.

**The fix:** both tools now return `is_complete`, and when the answer was capped
they carry a `warning` in plain language naming the limit and how to raise it. A
`COUNT` is marked complete, because nothing was truncated. An explicit `SAMPLE`
supplied by the caller is still respected rather than doubled.

**Proof:** `tests/test_tools/test_query.py::TestResultCompleteness`

## Finding 4 — a timed-out query kept running

**Where:** `ConnectionManager.execute_command()`

**What happened:** the command ran on a daemon thread, and the caller waited on an
event with a timeout. When the timeout fired, a `TimeoutError` was raised — and
that was all. The thread stayed alive, the query kept running on the server, and
the session it was using was handed straight to the next request.

**What it cost:** three compounding problems. The database kept doing work nobody
was waiting for. Abandoned threads accumulated under load. And the next request
reused a session with an in-flight command on it, so replies could interleave.

**The fix:** uopy exposes no way to cancel a command in flight, so the honest
remedy is to close the session the query is running on. The socket drops, the
server abandons the command, and the reconnect repaired in Finding 2 makes the
next request safe. Commands are now also serialized with a lock, because a uopy
session is a single conversation with the server. Abandoned queries are counted and
exposed as `abandoned_query_count`, so a rising number is visible rather than silent.

**Proof:** `tests/test_connection.py::TestQueryTimeouts` and
`::TestConcurrentCommands`

## Finding 5 — authentication state did not survive a restart

**Where:** `auth/storage.py`

**What happened:** every registered client, issued token and in-flight login was
held in dictionaries on the process. The class documents this honestly, but the
consequences are heavier than they first appear.

**What it cost:** three things. A restart -- a deploy, a crash, a patch window --
signed every user out and forced them back through the identity provider. The
service could not be made redundant, because a second instance behind a load
balancer would reject tokens the first had issued. And there was no way to revoke
a token except by restarting, which revoked everyone's.

**The fix:** the OAuth bridge's clients, codes, tokens and pending sign-ins are
kept in SQLite, now in the settings database's `oauth_*` tables, so a restart
signs nobody out. One deliberate choice goes beyond merely persisting:

- **Bearer tokens are stored as SHA-256 hashes, never in the clear.** The lookup
  is by hash, and the raw value is put back on the returned object for the caller.
  A stolen database file therefore yields no usable credentials -- the same reason
  passwords are not stored in the clear. Raw tokens held in memory are survivable; writing
  them to disk would not be.
**Proof:** `tests/test_auth/test_storage.py`, including a restart
simulated with a second instance on the same file, and an assertion that the raw
token bytes never appear in the database.

## Finding 6 — the audit trail could not name who acted

**Where:** the audit trail (now `guard.py`, writing the settings database's audit table)

**What happened:** every record carried `session_id`, generated when the server
process started. It identified the *process*, not the person.

**What it cost:** the server went to real trouble to authenticate people through
Duo, Auth0 or Okta, and then discarded the answer. Asked "who ran that query
against the customer file on Tuesday?", the log could say only that a query was
run. That is a debugging aid, not an audit trail, and it is the gap that matters
first in a regulated environment.

**The fix:** a caller identity now travels with the request (`identity.py`), and
in team mode every audit row names the person, the connection and the outcome.
Passwords are never written, and secret-named parameters are redacted.

**Proof:** `tests/test_guard.py`

## Finding 7 — every caller reached the database as the same account

**Where:** `server.py::get_connection_manager()` and `ConnectionManager`

**What happened:** a single module-level `ConnectionManager` served the whole
process, built from the credentials in the server's own environment. Whoever was
asking, the query arrived at Universe under one account.

**What it cost:** this is the finding that decides whether the server can go near
regulated data. Universe has its own file and field security, and it was being
shown a service account rather than the person. Nothing the database could do
would restrict Alice differently from Bob, because it never saw either of them.
The single shared session also meant one person's transaction state and open file
handles were shared with everyone else's requests.

**The fix:** a `ConnectionRegistry` holds one `ConnectionManager` per route (a
connection plus a database login) and hands out the one belonging to the current
caller. In team mode each connection uses either one shared login or each
person's own U2 login, set on the admin site; a caller with no personal login on
a per-person connection is **refused**, never given the shared account.

Composition rather than rewriting kept this contained -- `ConnectionManager` was
left as the per-login object it already was, and gained only the credentials it
connects with.

**Proof:** `tests/test_registry.py`, `tests/test_routing.py` and `tests/test_identity.py`

## Finding 8 — the tools that touch data had no tests at all

**Where:** `tests/test_tools/`, which contained only an empty `__init__.py`

Finding 0 explained why: the test doubles modelled an API the server had stopped
calling, so no tool test could have been written against them. With the doubles
rebuilt, the tools became testable, and every module that touches business data
now has coverage.

The emphasis is deliberately on the guarantees an operator actually relies on,
rather than on line coverage for its own sake:

- **Read-only mode leaves the data untouched**, not merely returns an error. Each
  refusal is asserted twice: once on the response, once on the stored record.
- **Writes and deletes require explicit confirmation**, and an unconfirmed call
  changes nothing.
- **A refused command never reaches the server** — asserted against the commands
  the mock session actually received.
- **MultiValue structure survives a write-then-read round trip**, which is the
  property the whole project exists to preserve.
- **A batch read names what it could not find** instead of silently returning
  fewer records than asked for.
- **A nested transaction is refused without disturbing the open one.**

At the time of this work the suite held 203 tests, the tool package had 65%
statement coverage, and all 6 tool modules had tests.

Two things surfaced while writing them. The mock subroutine had to gain the real
`set_arg`/`get_arg` API, because the previous double exposed a bare argument list
the production code never uses -- the same drift as Finding 0, one layer down.
And `delete_knowledge` requires confirmation, which is good behaviour that was
nowhere asserted; it is now.

## Reviewing the remediation itself

Every fix above is new code, and new code is new attack surface. Proving the
original defects are gone says nothing about whether closing them opened
something else, so the fixes were reviewed as adversarially as the original code.

Three things were done. `bandit` was run across `src/` and reported no high or
medium findings beyond a pre-existing default of binding to all interfaces.
Each new mechanism was then examined for what happens when it *fails*, on the
principle that a security control is only as good as its failure mode. Finally
`tests/test_hardening_regressions.py` attacks the remediations directly.

Four defects were found in the remediation. All four are fixed, and all four
were introduced by the remediation itself.

### R1 — the durable auth store reintroduced authorization-code replay

The in-memory store consumed a one-time code with `dict.pop()`, which is atomic.
The SQLite backend replaced that with a `SELECT` followed by a separate `DELETE`,
leaving a window in which two requests both read the code before either removed
it.

A timing test alone did not catch this: the window is small enough that a naive
race usually loses, and the first version of the test passed while the bug was
present. Widening the window deliberately — delaying the read, then racing forty
threads — made it unambiguous: **forty threads exchanged the same authorization
code**. It is now claimed atomically with `DELETE ... RETURNING`, and the same
test yields exactly one success.

This is the most serious finding in the document, and it was introduced
by the remediation. It is worth stating plainly: making state durable is not a
behaviour-preserving change, because atomicity that came free in memory has to
be re-established explicitly in a database.

### R2 — identity resolution failed open

`current_caller()` caught every exception from the resolver and fell back to the
unauthenticated local operator. A caller who could make token lookup fail would
still reach the database and have their
actions recorded as `local`, which is identity laundering against the audit
trail it had just added.

Resolution now distinguishes two situations. No resolver installed means stdio
mode, where the local operator is the honest answer. A resolver installed means
authentication is in force, and a failure to name the caller raises rather than
downgrading.

### R3 — files holding credentials were world-readable

The database file and its directory were created with default permissions. They
are now restricted to their owner where the operating system enforces that;
Windows ignores POSIX bits, so the test is skipped there and the deployment
documentation carries the ACL requirement instead.

### R4 — per-user connections grew without limit

One connection per caller becomes one connection per caller *ever seen*, which a
crowd of authenticated users could turn into exhaustion of the database's own
connection limit. The registry now holds a bounded, least-recently-used set
governed by `U2_MAX_CONNECTIONS`; an evicted caller simply reconnects on their
next request.

## Finding 9 — the HTTP transport served an unauthenticated database to the network

The legacy SSE transport performed no authentication, bound to `0.0.0.0` and
allowed CORS `*` with credentials: anyone who could reach the port could write and
delete records. The SSE transport has since been removed, and every network
transport now authenticates. `U2_HTTP_HOST` defaults to `127.0.0.1`,
`U2_HTTP_CORS_ORIGINS` defaults to empty, and a literal `*` is refused because it
cannot be combined safely with credentials.

## Continuous assurance

A one-off audit describes the day it was run. The CI pipeline now fails the build
on either of two conditions, so the assurance renews itself:

- `bandit -r src/ --severity-level medium --confidence-level medium` — currently
  clean, with the two findings it raised both resolved rather than suppressed.
  The composed `DELETE ... RETURNING` statement was rewritten as module constants
  so no table name is built at runtime, and the bind-address finding became
  Finding 9.
- `pip-audit` — currently reports no known vulnerabilities in the dependency tree.

Both run before the build job, which now depends on them.

## Finding 10 — TCL could escape to the operating system

**Where:** `utils/safety.py::DEFAULT_BLOCKED_COMMANDS`

This is not an edge case. `execute_tcl` is a first-class tool the model calls
routinely, and the blocklist named nine destructive file verbs while omitting
every escape route out of the database.

**What it cost:** `SH -c '...'` and `!ls` reach a shell on the database server.
`OSDELETE`, `OSWRITE` and `OSREAD` reach its filesystem. `RUN`, `BASIC` and
`CATALOG` compile and execute arbitrary code. `LOGTO` leaves the configured
account, escaping every other control in the server. The SQL verbs Universe also
accepts -- `DROP`, `GRANT`, `UPDATE` -- were likewise absent. In short, one tool
call away from remote code execution, in the default configuration.

`execute_tcl` still refuses `BASIC`, `CATALOG` and `RUN`. Compiling and cataloging
are possible only through `compile_program` and `catalog_program`. Each needs its
own permission (`basic.compile`, `basic.catalog`) and is refused in read-only mode.
Each builds its command itself, from a file name matching `U2_BASIC_FILES` and
program names limited to letters, digits, `.`, `_` and `-`, and catalogs locally
only.

The blocklist was also evadable by formatting. `!ls` produced a first word of
`!LS`, which matched nothing, so the shell escape passed even when the verb was
listed.

**The fix:** the blocklist now enumerates every escape route by category --
shell and OS access, code compilation and execution, account switching, system
state -- with the reason each is there. A leading shell metacharacter is treated
as an escape rather than parsed as a verb, and verdicts are unaffected by case or
leading whitespace.

**Proof:** `tests/edge/test_adversarial_input.py` — 59 tests, each escape verb
asserted twice: refused by the validator, and never reaching the server.

## Finding 11 — the row cap could be removed by a file name

**Where:** `tools/query.py::execute_query`

The cap was skipped whenever the text `SAMPLE` appeared anywhere in the query, so
a file called `SAMPLES` or a field called `SAMPLE.DATE` silently removed the row
limit — and, after Finding 3, the answer then claimed to be complete. The test is
now for an actual `SAMPLE n` clause.

## Finding 12 — saved knowledge could forge other topics

**Where:** `utils/knowledge.py`

When notes were one Markdown file, a line beginning with `##` in saved content
created a new section, inventing or overwriting a topic. Notes are now rows in
SQLite, one per topic, so content cannot spill into another topic.

## Finding 13 — a reconnect storm opened one session per caller

**Where:** `ConnectionManager.get_session()`

Nothing serialized establishing a session, so a burst of requests arriving to find
none open would each create one. Twenty concurrent callers opened twenty database
connections for a single slot: a connection leak invisible until the server runs
out.

As with the authorization-code race, a naive concurrency test passed while the
bug was present. Holding the window open made it deterministic. Session
establishment is now serialized separately from command execution, so a burst
opens exactly one.

## Fuzzing, and a review as a stranger would read it

Two passes remained after the scenario suites: properties checked against inputs
nobody would write by hand, and a read-through of the project's own diff as though
it were someone else's pull request. Both found defects.

### Property-based fuzzing

`tests/edge/test_fuzz_parsers.py` states 21 properties and checks each against
hundreds of generated inputs drawn from the whole of Unicode, including the
MultiValue delimiters themselves. The properties are chosen so that a failure is
always a real defect: parsers never raise, output is always JSON-encodable, no
delimiter or control character ever survives sanitizing, sanitizing is
idempotent, and a blocked verb is refused however it is dressed.

**Finding 15 — punctuation disguised a blocked verb.** The fuzzer produced
`basic:`, which was allowed. The verb was taken by splitting on whitespace, so
`BASIC:` did not match `BASIC` and passed. Every blocked verb could be disguised
the same way, which quietly undid Finding 10 for anyone who thought to try it.
The verb is now the leading run of the characters a verb is made of, stopping at
the first character that is not one, so punctuation cannot hide it.

This is exactly the defect class hand-written tests miss. Nobody writes `SH:` as
a test case, because nobody types it.

### Reading the diff as a stranger

**Finding 16 — the server restricted a directory it did not create.** Tightening
permissions on the database file was right; doing the same to its parent was
not. Pointing the database at a shared directory would have set that
directory to owner-only, locking out everything else using it. Only a directory
this server creates is restricted now.

**Finding 17 — a slow eviction froze every caller.** The registry closed an
evicted connection while holding its lock. The connection being evicted is often
the one that stopped responding, so closing it can block for the length of a
network timeout while every other caller waits behind it. Slots are now removed
under the lock and closed outside it.

**Finding 18 — writing an audit record opened a connection slot.**
`_current_login` asked the registry for the caller's connection manager, and
asking creates a slot. Recording that work had happened could therefore evict
somebody else's session. Credentials are now resolved directly, with no side
effect.

Findings 16 to 18 were all introduced by earlier fixes, and none of them would have
been found by running the tests. They came from reading the code again with one
question in mind: what else does this touch?

## The type errors were hiding two real bugs

CI runs `mypy src/`, and it reported 14 errors, so that step was
already failing. It would have been easy to
silence them. Read instead, two of them turned out to be defects in the refresh
flow, which is the path every session takes about an hour in.

**Finding 19 — refreshing a token crashed.** `exchange_refresh_token` read
`refresh_token.resource`, and the SDK's `RefreshToken` has no such attribute. Any
client attempting to refresh got an `AttributeError`. mypy had been saying so
plainly: `"RefreshToken" has no attribute "resource"`.

**Finding 20 — a refreshed token belonged to nobody.** The new tokens were stored
with `user_subject=""` under a comment reading "Preserved from original auth". It
was not preserved. From the first refresh onward the audit trail would record an
empty user, and per-person credential resolution would fail outright — so the
identity work of Findings 6 and 7 quietly stopped applying an hour into every
session. The rotation now recovers the stored token first and carries its subject,
claims and resource across, and refuses a token this server did not issue.

The remaining errors were smaller but each named something worth fixing rather
than suppressing: a token could be stored against a `None` client id, so it could
never be revoked by client or attributed in a log; token introspection built an
HTTP request with `None` credentials, failing inside the transport rather than
reporting the configuration error it was; a client authentication method outside
the four the specification defines would have been advertised verbatim; and the
issuer URL was accepted unvalidated, so a malformed one failed at the first
sign-in rather than at startup.

`mypy src/` now reports no issues across 37 files, with `strict_equality`,
`warn_unused_ignores` and `warn_redundant_casts` added and the two stale
`type: ignore` comments removed. Nothing is suppressed to achieve it.

## A seam for evaluating this server without a database

Licensing means most people who might assess this server have no Universe
instance to point it at, and none can be redistributed. `U2_DRIVER` names the
library the server talks to the database through: `uopy` by default, or any
module providing the same surface.

Three things keep the seam from becoming a liability:

- **The default is unchanged and asserted.** With nothing configured the server
  loads `uopy`, and a test says so, because a seam added for evaluation is worth
  nothing if it alters production behaviour.
- **A replacement is checked at load, not at first use.** A driver missing any of
  the six names this server calls is refused at startup. A driver that loads and
  then fails mid-request is far harder to diagnose.
- **A replacement announces itself.** Running against anything other than a
  database logs a warning at startup, so nobody reading a log later mistakes the
  figures for production data.

## Still to come


