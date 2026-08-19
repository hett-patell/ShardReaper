---
name: hunt
description: Rich engagement scaffolder — scope.md (BugHunter-compatible) + findings/evidence/recon/reports workspace + engagement assertion. Usage: /hunt <dir> [--mode red-team|wapt] [--seeds ...] [--in-scope ...]
---

# /hunt — scaffold the kill

Invoking `/hunt` asserts the operator holds written authorization for the
named scope. The deliverable is a reproducible, remediable finding; an
out-of-scope host stops the run rather than widening it.

## What it creates

```
<dir>/
├── scope.md     <- in/out/seed patterns (markdown, BugHunter-compatible)
├── scope.json   <- the same scope, machine-readable (the code gate)
├── state.json   <- engagement state + ledger
├── notes.md     <- engagement frame + mode + objective
├── findings/    evidence/    recon/    reports/
```

## Usage

```
shardreaper hunt tgt/ --name acme --mode red-team \
    --seeds http://acme.com --in-scope acme.com --out-of-scope admin.acme.com
shardreaper hunt tgt/ --mode wapt          # web-app pentest framing
```

Fill `scope.md`, then: `shardreaper run tgt/ --phases recon,analyze,plan,attack,report`.
