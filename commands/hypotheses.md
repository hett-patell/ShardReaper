---
name: hypotheses
description: Hypothesis lifecycle ledger — probe budgets, no-evidence cutoffs, and tombstones with the recorded reason. Dead theories are never resurrected. Usage: /hypotheses <dir>
---

# /hypotheses

Theories are tracked, not vibed. Every attack-plan item becomes a
hypothesis with:

- **budget** — max probes before the theory dies
- **cutoff** — max CONSECUTIVE probes without evidence (evidence resets it)
- **tombstone** — when killed, the REASON is recorded in cross-engagement
  memory (`hypotheses.jsonl`), and the plan/attack phases refuse to run a
  tombstoned theory again, citing the reason

## Usage

```
/shardreaper hypotheses eng
```

A dead theory with a recorded reason is progress — it is one less
resurrection to pay for. Running theories cost the engagement its most
scarce resource: the next pivot.
