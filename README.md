# APS delegation layer for mcp-clickhouse

A runnable example of the delegation layer on top of the
`UserPassthroughMiddleware` sketch from
[ClickHouse/mcp-clickhouse#155](https://github.com/ClickHouse/mcp-clickhouse/issues/155).

The pass-through answers one question: who is connecting. It maps an
authenticated principal to a ClickHouse user, and native RBAC takes over from
there. That is the right answer for the case in the issue: humans with
accounts.

This adds the layer for the case the issue raises next: agents. An agent
acting for a user is not the user. Running it as the user hands it the user's
full grant. What an agent needs is a narrowed, time-bound subset, and a record
of what it was allowed to do that someone else can check later.

## What it adds

1. A scoped, time-bound delegation. The agent holds a signed grant for
   specific kinds of calls with an expiry. It cannot exceed that grant, and
   the ClickHouse user its calls run as is derived from it. A read-only
   delegation runs as a ClickHouse user that the server keeps read-only.

2. A signed receipt per tool call. `query_log` records what ran, attributed
   to whoever connected. A receipt records what was authorized: the decision,
   the delegation it came from, signed at decision time and verifiable by a
   third party that does not trust the server. A denied call is recorded too:
   the refusal is as auditable as the approval.

These compose with the pass-through. They do not replace it.

## Run it

```
pip install agent-passport-system clickhouse-connect
```

A local ClickHouse is enough. Start one and point the demo at it with the
same password on both sides:

```
docker run -d --name ch -p 8123:8123 -e CLICKHOUSE_PASSWORD=demo -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 clickhouse/clickhouse-server
export CLICKHOUSE_URL=http://localhost:8123 CLICKHOUSE_PASSWORD=demo
python examples/run_demo.py
python examples/tamper_demo.py
python tests/test_scope.py
```

The demo creates a read-only ClickHouse user, `aps_agent_ro`, so the
connecting user needs access management (the extra docker variable above).

Connection is read from `CLICKHOUSE_URL`, `CLICKHOUSE_USER`, and
`CLICKHOUSE_PASSWORD`.

The demo issues a read-only delegation to an agent, simulates five tool
calls with the mcp-clickhouse v0.7.0 tool names, and writes one signed
boundary receipt per call into ClickHouse. The calls are not sent through
mcp-clickhouse. Each permitted call runs its SQL against ClickHouse as the
agent's user:

```
[derive] agent calls run as ClickHouse user 'aps_agent_ro' (read only on the server)

[dispatch] agent runs 5 MCP tool calls:
  INSIDE  list_databases  clickhouse:read   receipt=...
  INSIDE  list_tables     clickhouse:read   receipt=...
  INSIDE  run_query       clickhouse:read   receipt=...
          sql: SELECT count() FROM system.tables
  OUTSIDE run_query       clickhouse:write  receipt=...
          sql: DROP TABLE important_data
          not run: denied: clickhouse:write not in ['clickhouse:read'] (scope_not_authorized)
  INSIDE  run_query       clickhouse:read   receipt=...
          sql: WITH 1 AS x INSERT INTO aps_demo_events VALUES (1)
          refused by ClickHouse: aps_agent_ro: Not enough privileges

[verify] 5/5 receipts verified against the store
```

Each call has a required outcome. The demo exits 1 if any call ends
differently, if a receipt is missing, or if any receipt fails verification.
The tamper demo exits 1 if the altered row still verifies.

## Two layers, and which one is the boundary

In mcp-clickhouse v0.7.0 one tool, `run_query`, carries every SQL statement,
so the scope a `run_query` call needs comes from its statement. A statement
whose first word is SELECT, WITH, SHOW, DESCRIBE, DESC, EXPLAIN or EXISTS
needs `clickhouse:read`. Everything else needs `clickhouse:write`, including
anything the check cannot read, such as `DROP/**/TABLE`. There is no tier
below write, so a spelling trick can only raise what a call needs. A write
grant covers every statement, destructive ones included, and runs as the
full user, so this example only demonstrates read grants. Every delegation
that does not authorize `clickhouse:write` runs as the read-only user, even
one that adds unrelated scopes such as `files:read`.

That label is a policy decision, not the security boundary. The last call
shows why. It starts with WITH, so it is labelled read and permitted, but it
writes. The boundary is the ClickHouse user a read delegation runs as. Its
`readonly=1` is fixed on the server and it holds SELECT only, so ClickHouse
refuses the write. The receipt for that call records what was authorized,
not what the database did.

A client-side setting is not a substitute. A client created with
`settings={"readonly": 1}` still accepts a per-query `readonly=0`, and
mcp-clickhouse sends `readonly=0` per query when
`CLICKHOUSE_ALLOW_WRITE_ACCESS=true`. For a user whose `readonly` is fixed on
the server, mcp-clickhouse reads the server's value and keeps it.

The receipts live in a `aps_mcp_receipts` table next to `query_log`. They
verify by reading them back out of ClickHouse, so the store does not need to
be trusted: tamper a row and the signature stops matching.

## How it maps to the middleware

The middleware shape is unchanged from the maintainer's example. The function
flagged as deployment-specific, `lookup_clickhouse_credentials`, is where this
layer slots in:

- `src/delegation_resolver.py` resolves the principal's delegation (in a real
  deployment, from your system of record).
- `src/middleware.py` labels the call, and for `run_query` its statement,
  checks it against the delegation scope, and picks the ClickHouse user the
  call runs as.
- The decision is recorded as an `AuthorityBoundaryReceipt`: `inside` for an
  authorized call, `outside` for one the delegation never granted.

## What a receipt proves, and what it does not

A boundary receipt proves the tool was checked against the agent's delegated
authority, and that the record is intact and recomputable. It does not prove
the tool's runtime effect matched the request, and it asserts nothing about
the data the tool returned. That limit is written into every receipt's
`does_not_assert` field, on purpose.

Built on the [Agent Passport System](https://github.com/aeoess/agent-passport-system),
an open Apache 2.0 protocol for agent identity, scoped delegation, and signed
receipts.
