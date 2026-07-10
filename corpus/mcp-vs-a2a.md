# MCP vs A2A — the two agentic-web protocols

Two complementary standards, both now under Linux Foundation stewardship.

## MCP (Model Context Protocol)

Created by Anthropic. Standardizes how a single agent connects to external
tools, data sources, and services — the "USB-C port" for tools. An MCP server
exposes tools/resources; an MCP client (the agent runtime) calls them. Scope:
one agent ↔ its tools.

## A2A (Agent-to-Agent)

Created by Google. Standardizes how independent agents discover each other and
collaborate as peers. Its core primitive is the **Agent Card** — a JSON
document at a well-known URL describing an agent's capabilities, inputs,
outputs, and required auth. A planner can query a registry of Agent Cards and
delegate a task to a capable peer without hardcoded knowledge. Scope: agent ↔
agent.

## How they fit together

Most real systems use both: MCP for an agent's tool connections, A2A for
coordination between agents. The winning outcome is not one protocol but an
ecosystem where they compose. Registries (discovery), identity/verification,
and trust layer on top.

See also: agent-capability-tokens.
