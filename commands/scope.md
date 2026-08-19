---
name: scope
description: Deterministic pre-flight gate — verify a target is authorized BEFORE any touch. Usage: /scope <target> [--scope <file>]
---

# /scope

The gate. Every action in an engagement passes through it. Enforced in code,
not by judgment: deny wins, default deny.

## Usage

```
/scope api.corp --scope eng/scope.json
/scope 10.0.0.5 evil.net --in-scope 10.0.0.0/24
```

Prints `IN-SCOPE` / `OUT-OF-SCOPE <reason>`; exits non-zero when any target is
out of scope — so it can gate automation.

## Rules

- Run before ANY contact with a target. An OUT-OF-SCOPE result is a hard stop.
- Deny wins: matching both in-scope and out-of-scope rules ⇒ out of scope.
- Out of scope is never touched — even to "prove" something. Adapt the
  technique or drop it.
