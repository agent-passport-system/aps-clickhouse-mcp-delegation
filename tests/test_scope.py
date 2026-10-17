"""Policy labels for run_query statements. Run: python tests/test_scope.py"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from middleware import statement_scope, tool_to_scope, clickhouse_overrides_from_delegation

CASES = {
    "SELECT 1": "read",
    "  -- note\n select 1": "read",
    "/* c */ WITH a AS (SELECT 1) SELECT * FROM a": "read",
    "(SELECT 1)": "read",
    "SHOW TABLES": "read",
    "DESCRIBE TABLE t": "read",
    "EXPLAIN ESTIMATE SELECT 1": "read",
    "EXISTS TABLE t": "read",
    # Everything that is not a plain read needs clickhouse:write, however it is spelled.
    "DROP TABLE t": "write",
    "DROP/**/TABLE t": "write",
    "/**/DROP TABLE t": "write",
    "drop table t": "write",
    "SELECT/**/1": "write",
    "INSERT INTO t VALUES (1)": "write",
    "TRUNCATE t": "write",
    "ALTER TABLE t DELETE WHERE 1": "write",
    "CREATE OR REPLACE TABLE t (a Int8) ENGINE = Memory": "write",
    "OPTIMIZE TABLE t": "write",
    "": "write",
    None: "write",
    "/* unterminated": "write",
    "-- only a comment": "write",
}

failures = [(q, statement_scope(q), want) for q, want in CASES.items() if statement_scope(q) != want]
assert tool_to_scope("list_tables") == "clickhouse:read"
assert tool_to_scope("run_query", "DROP/**/TABLE t") == "clickhouse:write"
assert tool_to_scope("run_chdb_select_query", "SELECT 1") == "clickhouse:run_chdb_select_query"
def user_for(scope):
    return clickhouse_overrides_from_delegation({"scope": scope}, "ro", "full")["username"]

assert user_for(["clickhouse:read"]) == "ro"
assert user_for(["clickhouse:read", "files:read"]) == "ro"
assert user_for(["files:read"]) == "ro"
assert user_for([]) == "ro"
assert user_for(["clickhouse:write"]) == "full"
assert user_for(["clickhouse:read", "clickhouse:write"]) == "full"

if failures:
    for f in failures:
        print("FAIL", repr(f[0]), "got", f[1], "want", f[2])
    raise SystemExit(1)
print(f"ok: {len(CASES)} statements labelled as expected")
