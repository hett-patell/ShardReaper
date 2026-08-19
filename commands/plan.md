---
name: plan
description: Rank recon intel into an attack plan — findings first, services next, every item mapped to ATT&CK + atomic tests. Usage: /plan <engagement-dir>
---

# /plan

Turn intel into fire orders. The engine ranks every finding and open service
by severity and attaches the matching technique + Atomic Red Team tests. With
a brain configured (`REDAGENT_LLM_*`) it also ranks full attack chains.

## What it produces

- `state.json → plan[]`: each item has target, action, severity, ATT&CK
  technique, and the atomic tests that implement it
- Exposed sensitive paths → HIGH "confirm-and-exploit"
- Open ports → service enumeration items with technique hints
- Live web apps → deep-web-audit items

## Usage

```
/plan eng
redagent run eng --phases plan
```

## Rules

- Attack order: findings first (confirmed value), services next, then the long
  tail. Chains, not checklists.
- Re-plan whenever recon changes the surface.
