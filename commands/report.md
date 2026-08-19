---
name: report
description: Render the deliverable — client REPORT.md or platform submissions (HackerOne, Bugcrowd VRT-aware, Intigriti). Usage: /report <dir> [--platform h1|bugcrowd|intigriti]
---

# /report — ship it

## Flavors

- `shardreaper report eng/` — client red-team deliverable: chains, severity, ATT&CK mapping, evidence, next moves
- `--platform h1` — HackerOne: Weakness / Severity / Summary / Steps / Impact per finding
- `--platform bugcrowd` — VRT-mapped submission
- `--platform intigriti` — impact-first submission

## Rules

- Gate first (`/triage`) — killed findings are skipped by the platform renderers.
- Evidence hygiene: no operator PII, no victim data, no session cookies in the output.
- Every claim traces to a ledger entry.
