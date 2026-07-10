# Honeytokens & Canary Tokens

A honeytoken (a.k.a. canary token) is a decoy artifact — a fake API key, URL,
DB record, or tool — that has no legitimate use. It sits dormant; the moment
anything interacts with it, you have a high-signal alert that something
unauthorized happened, because nothing benign ever touches it.

## How they work

1. Generate a unique token with a built-in trigger (a unique URL or DNS name).
2. Place it where an adversary (or a hijacked agent) would plausibly find it.
3. Make it look valuable and legitimate.
4. Any interaction fires an attributable alert.

## Why they are powerful

- Near-zero false positives: no honest path reaches the token.
- Cheap and dormant: no impact on normal operation.
- Attributable: a unique token ties the event to a specific context.

## Applied to agents

Canary *tool definitions* (e.g. `dump_credentials`) or canary *endpoints* placed
in retrieved content detect indirect prompt injection with 100% precision: an
agent only calls them if it obeyed injected instructions. Pair with temporal
analysis — automated agents call fast and with low variance.

Deploy only in controlled honeypot environments explicitly designed to be
probed, never as offense against systems you do not own.

See also: indirect-prompt-injection.
