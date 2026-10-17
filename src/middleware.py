"""
Delegation layer on top of joe-clickhouse's UserPassthroughMiddleware sketch
(ClickHouse/mcp-clickhouse#155).

The middleware shape is unchanged from the maintainer's example. The function
he flagged as deployment-specific, the credential lookup, is where the APS
delegation layer slots in. On every tool call we:

  1. resolve the authenticated principal (same as the pass-through),
  2. resolve that principal's APS delegation and check the tool against its
     scope: out of scope is denied before the call runs,
  3. pick the ClickHouse user the call runs as from the delegation,
  4. record a signed artifact for the decision. A permit produces a signed
     action receipt (the agent did something it was authorized to do). A deny
     produces a signed decision recording the refusal. The protocol will not
     manufacture an authorization receipt for an action it denied.

The artifact is what makes the call auditable: it lives in a receipts table
next to query_log and verifies offline.
"""

from __future__ import annotations
import agent_passport as ap

# In the real server these come from:
#   from fastmcp.server.dependencies import get_context, get_access_token
#   from fastmcp.server.middleware import Middleware, MiddlewareContext, CallNext
#   from mcp_clickhouse.mcp_server import CLIENT_CONFIG_OVERRIDES_KEY
# The example provides a runnable harness in examples/run_demo.py that does
# not need a live server, so the decision logic can be exercised directly.

# Tool names as of mcp-clickhouse v0.7.0. There, one tool, run_query,
# carries every SQL statement, so the scope a call needs depends on the
# statement, not on the tool name.
READ_TOOLS = {"list_databases", "list_tables"}
QUERY_TOOL = "run_query"
READ_KEYWORDS = {"SELECT", "WITH", "SHOW", "DESCRIBE", "DESC", "EXPLAIN", "EXISTS"}


def _strip_leading_comments(sql: str) -> str:
    s = sql.lstrip()
    while True:
        if s.startswith("--"):
            nl = s.find("\n")
            s = "" if nl < 0 else s[nl + 1:].lstrip()
        elif s.startswith("/*"):
            end = s.find("*/")
            s = "" if end < 0 else s[end + 2:].lstrip()
        else:
            return s


def statement_scope(sql: str | None) -> str:
    """
    Label one SQL statement "read" or "write" for the policy decision.

    Only a statement whose first word is a read keyword is labelled read.
    Everything else, including anything this check cannot parse, needs
    clickhouse:write. There is deliberately no tier below write, so a
    spelling trick can only turn a read label into a write requirement,
    never weaken a write requirement.

    The label is not the security boundary. A statement such as
    "WITH 1 AS x INSERT ..." starts with a read keyword and is labelled
    read. The boundary is the read-only ClickHouse user a read delegation
    runs as (see clickhouse_overrides_from_delegation): the server refuses
    the write for that user whatever the label said.
    """
    words = _strip_leading_comments(sql or "").replace("(", " ").split()
    if words and words[0].upper() in READ_KEYWORDS:
        return "read"
    return "write"


def tool_to_scope(tool_name: str, query: str | None = None) -> str:
    """Map an MCP tool call to the APS scope token it requires."""
    if tool_name in READ_TOOLS:
        return "clickhouse:read"
    if tool_name == QUERY_TOOL:
        return f"clickhouse:{statement_scope(query)}"
    return f"clickhouse:{tool_name}"


def decide(delegation: dict, tool_name: str, query: str | None = None):
    """
    The authorization decision. The delegation is the policy: a call is
    permitted only if the delegation's scope authorizes it and the delegation
    has not expired. Returns (permitted: bool, required_scope: str, reason).
    """
    required = tool_to_scope(tool_name, query)
    in_scope = ap.scope_authorizes(delegation.get("scope", []), required)
    expired = ap.is_expired(delegation)
    permitted = in_scope and not expired
    if permitted:
        reason = "in_scope"
    elif expired:
        reason = "delegation_expired"
    else:
        reason = "scope_not_authorized"
    return permitted, required, reason


def clickhouse_overrides_from_delegation(
    delegation: dict, read_only_user: str, full_user: str
) -> dict:
    """
    Derive the ClickHouse identity the agent's calls run as.

    Only a delegation that authorizes clickhouse:write runs as the full
    user. Every other delegation, including one that adds unrelated scopes
    such as files:read next to clickhouse:read, runs as a ClickHouse user
    that the server itself keeps read-only (user settings readonly=1, marked
    READONLY, and SELECT grants only). That is the database boundary for
    anything short of a write grant.

    Client-side settings are not used for this. A client created with
    settings={"readonly": 1} still accepts a per-query readonly=0, and
    mcp-clickhouse sends readonly=0 per query when
    CLICKHOUSE_ALLOW_WRITE_ACCESS=true. For a user whose readonly setting
    is fixed on the server, the per-query value is refused.

    The password for each user comes from your deployment's secret store,
    as in the pass-through sketch.
    """
    can_write = ap.scope_authorizes(delegation.get("scope", []), "clickhouse:write")
    return {"username": full_user if can_write else read_only_user}
