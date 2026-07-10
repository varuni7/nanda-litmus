# Capability Tokens & Delegation for Agents

A capability token grants a bearer a specific, scoped permission — "read
dataset X for 10 minutes" — rather than broad identity-based access. They are a
good fit for multi-agent systems where an orchestrator hands narrow, temporary
powers to workers.

## Delegation (macaroon style)

An agent holding a token can mint a *strictly narrower* child token for another
agent without contacting the issuer. Each child is chained to its parent with an
HMAC: `child_seal = HMAC(parent_seal, caveat)`. Because you can only add
caveats, a holder can never widen scope, only restrict it.

## Cascading revocation

Because every descendant seal is derived from its ancestor's, revoking an
ancestor invalidates the entire subtree — no per-child bookkeeping. A verifier
recomputes the chain and rejects any token whose ancestor seal was revoked.

## Distribution

In a swarm the revocation set is replicated per verifier and spread by gossip; a
grow-only set (G-Set CRDT) converges regardless of order or loss. Safety is
monotone: once a verifier observes a revocation, it never accepts that token
again.

## Pitfalls

- Bind tokens to an audience so a leaked token can't be replayed by another agent.
- Enforce child TTL ≤ parent TTL.
- Never derive token identity from wall-clock time or an unseeded RNG if you need
  reproducible behavior.

See also: mcp-vs-a2a, indirect-prompt-injection.
