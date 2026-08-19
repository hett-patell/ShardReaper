---
name: pickup
description: Resume a target — hunt history, confirmed findings, already-tested techniques from the cross-engagement memory ledger. Usage: /pickup <host>
---

# /pickup — the model resume

Pick up where the last engagement left off on a target.

## What it shows

- Sessions and last-seen timestamps
- Confirmed findings (auto-captured by the engine)
- Techniques already tested (so they're never re-wasted)
- Operator notes from `/remember`

## Usage

```
/pickup target.com
shardreaper pickup target.com
```

## Rules

- Automatic capture: every confirmed finding lands in the ledger with no
  action from the operator. `/remember` is only for extra context.
- A technique on the tested list that produced nothing is a skip decision —
  don't re-test it on the same stack.
