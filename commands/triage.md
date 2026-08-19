---
name: triage
description: 7-Question Gate on findings — submit or kill, before any report time. Usage: /triage <dir> [finding ids] [--yes]
---

# /triage — the gate

Kills N/A submissions before they cost report time and validity.

## The 7 questions

1. In the operator's authorized scope?
2. Real impact demonstrated (not hygiene)?
3. Impact class accepted by the program?
4. Evidence captured?
5. Reproducible in ≤5 steps?
6. Duplicate of an existing finding? (must be NO)
7. Severity honest — not inflated, not under-sold?

## Usage

```
shardreaper triage eng/               # interactive, one finding at a time
shardreaper triage eng/ F001 F002     # gate specific findings
shardreaper triage eng/ --yes         # non-interactive pass (pipelines)
```

Gate results are stored on the finding — `/surface` shows kills, platform
reports skip them automatically.
