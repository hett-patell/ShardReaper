---
name: attack
description: Execute the plan — fire atomic tests at in-scope targets. Dry-run by default; --go executes. Every action logged with technique id. Usage: /attack <engagement-dir> [--go]
---

# /attack

Kick the doors in — all of them, in impact order. Every plan item is executed:
atomic tests rendered and fired, actions logged to the ledger, outcomes
captured as evidence.

## Usage

```
/attack eng                    # dry-run: renders every command, touches nothing
/attack eng --go               # execute (operator-authorized)
shardreaper atomic select --technique T1003
shardreaper atomic run --technique T1003 --index 0 --go
```

## Rules

- Dry-run first — see the exact commands before any `--go`.
- Every action is logged: technique id, target, outcome, evidence.
- First foothold → immediately think persistence (see /escalate, /persist).
- Never stop at the first win. The operator wants the domain.
