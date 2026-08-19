---
name: rack-check
description: The rack's own regression gate — AST structural check (no methods nested inside module functions) plus the raw pkill -f audit. Usage: /rack-check [--atomic <root>]
---

# /rack-check

"Fixed" means TESTED before the next engagement. Two structural checks run
here — and inside every `healthcheck`:

## 1. AST structural check

No function definitions nested inside module functions. Every nested def
that looks harmless is where a previous pass stashed a helper the runner
never re-discovers — the exact class of bug that cost real engagement time.

## 2. pkill self-match audit

Raw `pkill -f <pattern>` without a bracketed first character is flagged
across the rack (atomic test commands included). `pkill -f` matches its own
command line; `safe_kill` auto-brackets, and execution of raw unbracketed
patterns is banned at the atomic-runner gate.

## Usage

```
/shardreaper rack-check [--package shardreaper] [--atomic <atomic-red-team-root>] [--json]
```

Exit code 0 = rack clean. A violation is a STOP-THE-ENGAGEMENT event until
the rack is fixed and this command returns 0.
