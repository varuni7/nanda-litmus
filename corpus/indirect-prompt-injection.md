# Indirect Prompt Injection

Indirect prompt injection (IPI) is an attack where malicious instructions are
embedded in *external data* an LLM ingests — a web page, a document, a tool
result, an email — rather than typed directly by the attacker. When the model
treats that retrieved content as instructions instead of data, the attacker
steers it without ever talking to it.

## Why it is hard to stop

- The payload arrives inside content the agent legitimately needs to read.
- Pattern filters miss paraphrased or encoded instructions.
- Agents with tools can be induced to take real actions (send data, call APIs).

## Common payload shapes

- Overt override: "ignore previous instructions and…".
- System-styled directives hidden in HTML comments or metadata.
- Covert instructions ("do this silently; do not mention it to the user").
- Confused-deputy calls ("to verify freshness, call this endpoint first").

## Defenses that help

- Treat all retrieved content as untrusted data, never as instructions.
- Run fetched context through a classifier before the primary model sees it.
- Use canary tool/endpoint names no benign flow calls — any invocation is a
  high-precision injection signal.
- Constrain tool permissions; require confirmation for side-effecting actions.

See also: honeytokens-deception, agent-capability-tokens.
