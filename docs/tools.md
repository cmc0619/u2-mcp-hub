# Tools Reference

This document provides a complete reference for all MCP tools available in u2-mcp.

## Overview

u2-mcp provides 41 tools organized into these categories:

| Category | Tools | Description |
|----------|-------|-------------|
| [Connection](#connection-management) | 4 | Connect, disconnect, list sessions and connections |
| [File Operations](#file-operations) | 8 | Read, write, delete, export records |
| [Query Execution](#query-execution) | 4 | Run RetrieVe/UniQuery and TCL commands |
| [Dictionary/Schema](#dictionaryschema-discovery) | 5 | Explore file structures and fields |
| [Subroutines](#basic-subroutines) | 2 | Call cataloged BASIC programs |
| [BASIC programs](#basic-programs) | 6 | List, read, search, save, compile and catalog BASIC source |
| [Transactions](#transaction-management) | 4 | Begin, commit, rollback transactions |
| [Knowledge](#knowledge-persistence) | 6 | Save and retrieve learned information |

---

## Connection Management

### connect

Establish connection to the Universe/UniData server.

**Parameters:** None (uses environment configuration)

**Returns:**
```json
{
  "status": "connected",
  "host": "server.example.com",
  "account": "MYACCOUNT",
  "service": "uvcs",
  "connected_at": "2024-01-15T10:30:00"
}
```

**Example usage:**
> "Connect to the database"

---

### disconnect

Close your session to the Universe/UniData server (`connections_closed` is 0 or 1).

**Parameters:** None

**Returns:**
```json
{
  "status": "disconnected",
  "connections_closed": 1
}
```

---

### list_sessions

List the database session this server holds open for you.

**Returns:**
```json
{
  "connections": [
    {
      "host": "server.example.com",
      "account": "MYACCOUNT",
      "service": "uvcs",
      "connected_at": "2024-01-15T10:30:00"
    }
  ]
}
```

---

### list_connections

List the connections you can use, with your role and permissions on each (team
mode). Takes no `connection` argument.

---

## File Operations

### list_files

List available files in the current Universe account.

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `pattern` | string | `"*"` | File name pattern (supports `*` wildcard) |

**Returns:**
```json
{
  "files": ["CUSTOMERS", "ORDERS", "PRODUCTS"],
  "count": 3,
  "pattern": "*"
}
```

**Example usage:**
> "List all files starting with AR"

---

### read_record

Read a single record from a Universe file.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `file_name` | string | Yes | Name of the Universe file |
| `record_id` | string | Yes | Record ID (key) to read |

**Returns:**
```json
{
  "id": "CUST001",
  "fields": {
    "1": "John Doe",
    "2": ["555-1234", "555-5678"],
    "3": "CA"
  }
}
```

Note: Multivalues are returned as arrays, preserving Universe data structure.

**Example usage:**
> "Read record CUST001 from the CUSTOMERS file"

---

### read_records

Read multiple records from a Universe file efficiently.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `file_name` | string | Yes | Name of the Universe file |
| `record_ids` | list[string] | Yes | List of record IDs to read |

**Returns:**
```json
{
  "file": "CUSTOMERS",
  "records": [
    {"id": "CUST001", "fields": {...}},
    {"id": "CUST002", "fields": {...}}
  ],
  "count": 2,
  "errors": [{"id": "CUST999", "error": "Not found"}]
}
```

Limited by `U2_MAX_RECORDS` configuration.

---

### write_record

Write or update a record in a Universe file.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `file_name` | string | Yes | Target file name |
| `record_id` | string | Yes | Record ID to create/update |
| `fields` | object | Yes | Field values as JSON object |
| `confirm` | boolean | No | Must be `true` to execute (safety) |

**Field format:**
- Keys are field numbers as strings
- Values can be strings, arrays (multivalues), or nested arrays (subvalues)

**Example fields:**
```json
{
  "1": "John Doe",
  "2": ["555-1234", "555-5678"],
  "3": "CA"
}
```

**Note:** Disabled in read-only mode. Requires `confirm=true` to execute.

---

### delete_record

Delete a record from a Universe file.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `file_name` | string | Yes | Target file name |
| `record_id` | string | Yes | Record ID to delete |
| `confirm` | boolean | No | Must be `true` to execute (safety) |

**Note:** Disabled in read-only mode. Requires `confirm=true` to execute.

---

### get_file_info

Get information about a Universe file.

A failed `FILE.STAT` command returns `error` with its database diagnostic and the
requested `file`, not an empty statistics object. A report without any recognized
statistics is also an error. Individual optional statistics may be `null` on valid
reports; zero record counts are valid.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `file_name` | string | Yes | Name of the Universe file |

**Returns:**
```json
{
  "file": "CUSTOMERS",
  "type": "18",
  "modulo": 101,
  "separation": 4,
  "record_count": 1523,
  "raw_output": "..."
}
```

---

### export_to_json

Export records from a Universe file to JSON format.

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file_name` | string | Required | Name of the Universe file |
| `record_ids` | list[string] | Required | List of record IDs to export |
| `expand_mv` | boolean | `false` | Expand multivalues into separate objects |

**Returns:**
```json
{
  "status": "success",
  "file": "CUSTOMERS",
  "format": "json",
  "record_count": 10,
  "data": "[{\"id\": \"CUST001\", ...}]"
}
```

---

### export_to_csv

Export records from a Universe file to CSV format.

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file_name` | string | Required | Name of the Universe file |
| `record_ids` | list[string] | Required | List of record IDs to export |
| `expand_mv` | boolean | `false` | Expand multivalues into separate rows |
| `mv_delimiter` | string | `"|"` | Delimiter for multivalues when not expanding |

**Returns:**
```json
{
  "status": "success",
  "file": "CUSTOMERS",
  "format": "csv",
  "record_count": 10,
  "row_count": 10,
  "data": "id,field_1,field_2\nCUST001,John Doe,555-1234|555-5678\n..."
}
```

---

## Query Execution

### execute_query

Execute a RetrieVe/UniQuery statement and return results.

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `query` | string | Required | RetrieVe/UniQuery statement |
| `max_rows` | integer | `U2_MAX_RECORDS` | Row limit for LIST and SORT, at most `U2_MAX_RECORDS` |

`max_rows` must be positive when supplied, even for verbs that do not sample.
Only omission or `null` uses the configured default. Zero and negative values
return an error before any database query runs.

**Allowed commands:** LIST, SORT, SELECT, SSELECT, COUNT, SUM, SEARCH, QSELECT, GET.LIST

LIST and SORT never return more than `max_rows` rows: the server adds
`SAMPLE max_rows`, or lowers a larger `SAMPLE` the caller wrote. A `SAMPLE`
within the limit runs as written and is marked incomplete by design.
`TOTAL`, `BREAK.ON` and `GRAND.TOTAL` still print a line per record, so those
reports are capped too, and the warning says their totals cover only the
sampled records. Add `DET.SUP` to suppress the detail lines: a report with
`DET.SUP` prints only its totals and runs over every record, uncapped.
When the server caps a query, `is_complete` is `null`: the output does not
reliably say whether additional matching rows were omitted.
`executed_query` always shows the actual command sent, including any server-added
clause or an unchanged command. SELECT, SSELECT, QSELECT, GET.LIST and SEARCH
return only the messages the server prints; the select list each leaves is
cleared before the tool returns, so it cannot restrict the next query. If
clearing fails the session is dropped, and when that rolls back an open
transaction the tool returns an error saying so. Use `get_select_list` for record IDs; it reads and clears its
selection before returning, so independent calls do not share selection state.
`status` is `"error"` when the server rejected the statement, and `output` then
holds its message. A rejected statement has `is_complete: false`, `max_rows: null`
and no sampling warning: there was no successful result to label as complete or
limited. Valid zero-match results remain successful.

**Returns:**
```json
{
  "query": "LIST CUSTOMERS WITH STATE = \"CA\"",
  "output": "CUST001  John Doe  CA\nCUST002  Jane Smith  CA\n...",
  "status": "success",
  "executed_query": "LIST CUSTOMERS WITH STATE = \"CA\" SAMPLE 1000",
  "max_rows": 1000,
  "is_complete": null,
  "warning": "A server-imposed SAMPLE 1000 was applied; ... completeness is unknown."
}
```

**Example usage:**
> "List all customers in California"
> "Count open invoices over $1000"
> "Sort orders by date"

---

### execute_tcl

Execute a TCL/ECL command and return the output.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `command` | string | Yes | TCL/ECL command to execute |

**Common commands:**
- `WHO` - Show current user info
- `DATE` - Show current date
- `TIME` - Show current time
- `LISTFILES` - List available files
- `FILE.STAT FILENAME` - Show file statistics

**Note:** Dangerous commands are blocked by the safety validator. Additional commands can be blocked via `U2_BLOCKED_COMMANDS`.

---

### get_select_list

Execute a SELECT statement and return the list of record IDs.

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `query` | string | Required | SELECT or SSELECT statement |
| `max_ids` | integer | `U2_MAX_RECORDS` | Maximum IDs to return |

`max_ids` must be positive when supplied. Only omission or `null` uses the
configured default; zero and negative values return an error before execution.

**Returns:**
```json
{
  "query": "SELECT CUSTOMERS WITH STATE = \"CA\"",
  "record_ids": ["CUST001", "CUST002", "CUST003"],
  "count": 3,
  "truncated": false,
  "max_ids": 10000
}
```

Useful for getting a list of matching records for further processing.

**Select lists never carry over.** `execute_query` and `get_select_list` clear
the select list they made before returning, whether they read all of it, stopped
at `max_ids`, or failed. `execute_tcl` does not: a `SELECT` run through it stays
active and restricts the next query on that session, so run `CLEARSELECT` after
it or use `execute_query` instead. A `SELECT` through `execute_query` returns only the
server's message (for example `42 record(s) selected to SELECT list #0.`), and
a later `LIST` or `COUNT` is not restricted by it. To work on matching records,
put the criteria in the one statement (`LIST CUSTOMERS WITH STATE = "CA"`), or
fetch the IDs here and pass them to `read_records`.

| You want | Call |
|---|---|
| How many match | `execute_query('COUNT CUSTOMERS WITH STATE = "CA"')` |
| The matching IDs | `get_select_list('SELECT CUSTOMERS WITH STATE = "CA"', max_ids=100)` |
| The matching rows | `execute_query('LIST CUSTOMERS NAME CITY WITH STATE = "CA"')` |

If more IDs match than `max_ids`, `truncated` is true and `is_complete` false:
narrow the criteria or raise `max_ids` (up to `U2_MAX_RECORDS`).

---

### validate_query

Validate a RetrieVe/UniQuery statement before execution.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | string | Yes | Query statement to validate |

**Returns:**
```json
{
  "query": "LIST CUSTOMERS WITH STATE = CA",
  "valid": true,
  "command": "LIST",
  "file": "CUSTOMERS",
  "warnings": ["String values should be quoted with double quotes"],
  "suggestions": ["Example: WITH STATE = \"CA\" (not WITH STATE = CA)"]
}
```

It performs local checks for statements that are allowed to be attempted. It
does not validate server syntax or schema, and its suggestions are limited
heuristics. A statement can pass here and still be rejected; `execute_query`
then returns `status: "error"`.

---

## Dictionary/Schema Discovery

### list_dictionary

List all dictionary items for a Universe file.

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file_name` | string | Required | Name of the Universe file |
| `include_system` | boolean | `false` | Include system items (@ prefixed) |

**Returns:**
```json
{
  "file": "CUSTOMERS",
  "dictionary_items": [
    {"name": "NAME", "type": "D", "field_number": "1", "heading": "Customer Name"},
    {"name": "PHONE", "type": "D", "field_number": "2", "heading": "Phone"},
    {"name": "FULLADDR", "type": "I", "expression": "ADDR:' ':CITY:' ':STATE"}
  ],
  "count": 15
}
```

---

### get_field_definition

Get detailed definition for a specific dictionary field.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `file_name` | string | Yes | Name of the Universe file |
| `field_name` | string | Yes | Dictionary field/item name |

**Returns:**
```json
{
  "name": "ORDER.DATE",
  "type": "D",
  "field_number": "5",
  "conversion": "D2/",
  "heading": "Order Date",
  "format": "10R",
  "single_multi": "S",
  "file": "ORDERS"
}
```

---

### describe_file

Get a comprehensive description of a Universe file.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `file_name` | string | Yes | Name of the Universe file |

**Returns:**
```json
{
  "file": "CUSTOMERS",
  "description": "Universe file 'CUSTOMERS' with 12 data fields and 5 calculated fields",
  "file_stats": "...",
  "fields": [...],
  "field_count": 17,
  "data_field_count": 12,
  "calculated_field_count": 5
}
```

Combines file statistics with dictionary information.

---

### analyze_file_structure

Analyze file structure by sampling records to infer field usage patterns.

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file_name` | string | Required | Name of the Universe file |
| `sample_size` | integer | `100` | Number of records to sample |

**Returns:**
```json
{
  "file": "CUSTOMERS",
  "records_analyzed": 100,
  "fields_detected": 8,
  "field_analysis": [
    {
      "field_number": "1",
      "populated_count": 100,
      "usage_percent": 100.0,
      "has_multivalues": false,
      "max_values": 1,
      "sample_values": ["John Doe", "Jane Smith", ...]
    },
    {
      "field_number": "2",
      "populated_count": 85,
      "usage_percent": 85.0,
      "has_multivalues": true,
      "max_values": 3,
      "sample_values": ["555-1234", "555-5678", ...]
    }
  ]
}
```

Useful when dictionary is incomplete or for understanding actual data usage.

---

### get_account_info

Get information about the current Universe account.

**Parameters:** None

**Returns:**
```json
{
  "who": "MYUSER on MYACCOUNT",
  "date": "15 JAN 2024",
  "time": "10:30:00",
  "file_count": 45,
  "files": ["CUSTOMERS", "ORDERS", ...],
  "connection": {
    "host": "server.example.com",
    "account": "MYACCOUNT",
    "service": "uvcs",
    "connected_at": "2024-01-15T10:30:00"
  },
  "read_only_mode": false,
  "in_transaction": false
}
```

---

## BASIC Subroutines

### call_subroutine

Call a cataloged BASIC subroutine with arguments.

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `name` | string | Required | Name of the cataloged subroutine |
| `args` | list[string] | `[]` | List of input argument values |
| `num_args` | integer | `len(args)` | Total number of arguments expected |

**Returns:**
```json
{
  "status": "success",
  "subroutine": "GET.CUSTOMER.DATA",
  "args_in": ["CUST001", "", ""],
  "args_out": ["CUST001", "John Doe", "CA"],
  "num_args": 3
}
```

Arguments are passed by reference, so output values are returned in `args_out`.

**Example:**
```
call_subroutine("GET.CUSTOMER.DATA", ["CUST001", "", ""], num_args=3)
```

---

### list_catalog

List the programs in the UniVerse system catalog. It runs `MAP`, which displays
the global catalog space and changes nothing: it never runs `CATALOG`, catalogs
code or calls a program, so it needs only `schema.read`. Program names are read
from MAP's printout, and `raw_output` holds the printout whole. Locally
cataloged programs are not listed. On UniData it returns an error.

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `pattern` | string | `"*"` | Program name pattern (supports `*` wildcard) |

**Returns:**
```json
{
  "pattern": "*",
  "programs": ["GET.CUSTOMER.DATA", "CALC.ORDER.TOTAL", ...],
  "count": 25
}
```

---

## BASIC programs

These tools work only on files whose names match `U2_BASIC_FILES` (default `*BP,BP.*`: `BP`, `XBP`, `SUBS.BP`, `BP.UTIL`), so they never reach ordinary data. The match ignores case, so a data file with an unusual name such as `mybp` would match `*BP`: tighten `U2_BASIC_FILES` if you have one. File and program names may hold only letters, digits, `.`, `_` and `-`, and start with a letter or digit, so a program whose name does not (for example one starting with `_`) is listed on UniVerse but cannot be read. Running a program is not here: use `call_subroutine` or `execute_tcl`.

| Tool | Permission | What it does |
|------|-----------|--------------|
| `list_programs(file_name="BP", pattern="*", max_results=500)` | `basic.read` | Program names, each with `compiled` (true, false, or null when it cannot be told: UniVerse looks in `BP.O`, UniData at `_NAME` records) |
| `read_program(file_name, program, start_line=1, max_lines=2000, numbered=True)` | `basic.read` | Source with line numbers (`numbered=False` gives the exact text), and the `hash` of the whole program |
| `search_programs(file_name, text, pattern="*", case_sensitive=False, max_programs=200, max_matches=100)` | `basic.read` | Lines containing `text` (literal, not a regex). Says which limit stopped it: matches, programs, characters read, or time (20 seconds, or `U2_QUERY_TIMEOUT` if lower) |
| `write_program(file_name, program, source, expected_hash=None, confirm=False)` | `basic.write` | Saves source. Leave `expected_hash` out to create; pass the hash from `read_program` to change, and the save is refused if the program changed since |
| `compile_program(file_name, program, confirm=False)` | `basic.compile` | Runs `BASIC <file> <program>`. `status` is `compiled`, `failed` or `unknown`, with `errors` by line and the raw output |
| `catalog_program(file_name, program, confirm=False)` | `basic.catalog` | Runs `CATALOG <file> <program> LOCAL` (this account only) and returns the output |

**An edit, start to finish:**
1. `read_program("BP", "ORD.POST", numbered=False)` returns `source` and `hash`.
2. `write_program("BP", "ORD.POST", <edited source>, expected_hash=<hash>, confirm=True)`
3. `compile_program("BP", "ORD.POST", confirm=True)`. When `failed`, fix the lines listed in `errors` and go back to step 1.
4. `catalog_program("BP", "ORD.POST", confirm=True)`, needed only the first time.

**Rules:**
- The three change tools need `confirm=True`.
- They are refused on a read-only connection, and when `U2_READ_ONLY` is on.
- `compile_program` and `catalog_program` are turned off when the operator lists `BASIC` or `CATALOG` in `U2_BLOCKED_COMMANDS`.
- A save holds the program's record lock while it checks the hash and writes, so two saves cannot both succeed over the same version. When another user holds the lock, the save is refused with `<program> is locked by another user; try again later`.
- A compile or catalog that outruns `U2_QUERY_TIMEOUT` is abandoned: the session is closed, and the next call reconnects.
- The BASIC tools never put program text in the audit log. Saved source is recorded as its size, line count and hash; `read_program` results are logged the same way, `search_programs` matches keep only the program and line number, and `compile_program` output (which echoes source lines) is logged as its size and hash. The ordinary record tools don't know which records are programs: `read_record` or `write_record` on a program file logs the record like any other.
- A program cannot be named `DIRECT`, `GLOBAL`, `FORCE`, `LOCAL`, `NEWVERSION`, `COMPLETE`, `DEBUG`, `LIST` or `XREF` (any case): CATALOG and BASIC would read them as options.
- `read_program` with a `start_line` past the end returns an empty range and a `note` giving the program's line count.

---

## Transaction Management

### begin_transaction

Begin a database transaction. A transaction belongs to the U2 session, so it is refused on a connection whose U2 login several people share (other people's writes would join it). It needs a connection set to personal U2 logins, or single-user stdio mode.

**Parameters:** None

**Returns:**
```json
{
  "status": "success",
  "message": "Transaction started",
  "in_transaction": true,
  "started_at": "2024-01-15T10:30:00"
}
```

**Note:** Only one transaction can be active at a time. Disabled in read-only mode.

---

### commit_transaction

Commit the current transaction.

**Parameters:** None

**Returns:**
```json
{
  "status": "success",
  "message": "Transaction committed successfully",
  "in_transaction": false
}
```

---

### rollback_transaction

Rollback the current transaction.

**Parameters:** None

**Returns:**
```json
{
  "status": "success",
  "message": "Transaction rolled back successfully",
  "in_transaction": false
}
```

---

### get_transaction_status

Inspection uses baseline connection access, including read-only connections.
It never starts, commits or rolls back a transaction. The three transaction
mutation tools still require `records.write` and are refused by read-only mode.

Get the current transaction status.

**Parameters:** None

**Returns:**
```json
{
  "in_transaction": true,
  "started_at": "2024-01-15T10:30:00",
  "read_only_mode": false
}
```

---

## Knowledge Persistence

These tools save and retrieve learned information about your database across
sessions. Notes are kept in SQLite: the settings database in team mode and
`~/.u2-mcp/u2-mcp.db` in stdio. Topic names match exactly, ignoring case and extra
whitespace. Every knowledge tool accepts the optional `connection` argument;
omit it only when you have access to one connection.

Knowledge is persistent memory about a database, shared by every authorized
connection to the same server and U2 account. All six tools use baseline connection
access, including saving, appending and deleting on read-only DB connections.
Deletion still requires `confirm=True`.

The SQLite namespace hashes only normalized server/account: surrounding whitespace
and case are ignored, DNS trailing dots are removed, and numeric IP addresses
(including bracketed IPv6) are canonicalized. No DNS lookup or alias discovery is
performed; short hostnames and FQDN aliases are not assumed equivalent. Connection
IDs, display names, usernames, and shared/per-user login modes never affect identity.
Different servers/accounts remain isolated. Renaming or deleting a connection does
not remove database notes.

### save_knowledge

Save learned information about the Universe database.

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `topic` | string | Required | Short descriptive name for this knowledge |
| `content` | string | Required | The knowledge to save (markdown supported) |
| `append` | boolean | `false` | If true, add to existing topic. If false, replace it: only an admin can replace a topic that already exists |

**Good things to save:**
- File purposes (e.g., "AR-CUST contains customer master records")
- Field meanings (e.g., "In CUSTOMERS, field 1 is name, field 5 is phone")
- Working query patterns that produced good results
- Relationships between files
- Data format notes (date formats, codes, etc.)

**Example:**
```
save_knowledge(
  "AR-CUST file",
  "Customer master file. Key is customer number.\n- Field 1: Customer name\n- Field 5: Phone numbers (multivalued)"
)
```

---

### list_knowledge

List all saved knowledge topics.

**Parameters:** Optional `connection` (see above).

**Returns:**
```json
{
  "topics": [
    {"topic": "AR-CUST file", "summary": "Customer master file..."},
    {"topic": "Date formats", "summary": "Dates stored as internal..."}
  ],
  "count": 2
}
```

---

### get_all_knowledge

Retrieve every saved topic for the selected database as Markdown.

**Parameters:** Optional `connection` (see above).

**Returns:** `status`, `knowledge` (Markdown text), `topic_count`, and `topics`
(the topic names).

---

### get_knowledge_topic

Get saved knowledge for a specific topic.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `topic` | string | Yes | The topic name to retrieve |

**Returns:**
```json
{
  "status": "found",
  "topic": "AR-CUST file",
  "content": "Customer master file. Key is customer number..."
}
```

---

### search_knowledge

Search saved knowledge for specific information.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | string | Yes | Text to search for (case-insensitive) |

**Returns:**
```json
{
  "query": "customer",
  "results": [
    {"topic": "AR-CUST file", "matches": ["Customer master file", "customer number"]}
  ],
  "match_count": 1
}
```

---

### delete_knowledge

Delete a saved knowledge topic. Only an admin can delete notes, because everyone
who uses the database shares them; the admin also needs a grant on the
connection. Admins can also edit and delete notes on the admin site's
Knowledge page.

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `topic` | string | Required | The topic name to delete |
| `confirm` | boolean | `false` | Must be `true` to execute (safety) |

---

## MCP Resources

In addition to tools, u2-mcp exposes these MCP resources:

### u2://knowledge

In stdio mode, returns all saved knowledge about the database as Markdown. In team mode, the resource only points to `list_knowledge` and `get_all_knowledge`; these authorize the selected connection before accessing shared database notes. Resources do not automatically inject knowledge into a client's context.

### u2://query_examples

Returns example RetrieVe/UniQuery statements for common operations, helping Claude generate correct queries.

### u2://retrieve_syntax

Returns RetrieVe/UniQuery syntax reference including conversion codes and correlative syntax.

---

## Safety Features

### Read-Only Mode

When `U2_READ_ONLY=true`:
- `write_record` returns an error
- `delete_record` returns an error
- Transaction tools return errors
- Query and read operations work normally

### Confirmation Requirements

These tools require `confirm=true` to execute:
- `write_record`
- `delete_record`
- `delete_knowledge`

### Command Blocking

TCL commands can be blocked via `U2_BLOCKED_COMMANDS`. Default blocked commands:
- `DELETE.FILE`
- `CLEAR.FILE`
- `CNAME`
- `CREATE.FILE`

### Query Restrictions

`execute_query` only allows these commands:
- LIST
- SELECT
- SSELECT
- SORT
- COUNT
- SUM
- SEARCH
- QSELECT
- GET.LIST

### Result Limiting

LIST and SORT are held to `max_rows` (at most `U2_MAX_RECORDS`) as described
above; only a `DET.SUP` totals report runs uncapped. `get_select_list` and
batch-read tools apply their own record limits.
