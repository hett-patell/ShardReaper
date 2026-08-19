---
name: shardreaper-report
description: Reporting discipline — platform submissions (HackerOne, Bugcrowd VRT-aware, Intigriti), the 7-Question Gate before any write-up, evidence hygiene (redact operator PII, cookies, victim data), and the client-facing red-team deliverable. Use whenever a finding is confirmed and ready to ship.
---

# ShardReaper Report — Ship What Survives the Gate

## Doctrine

A finding without evidence is a rumor. A report without hygiene is a liability.
Gate first, write second, redact third, submit fourth.

## Workflow

1. **Gate before writing**: `shardreaper triage <dir> [finding-ids]` runs the
   7-Question Gate — scope, real impact, accepted class, evidence, 5-step
   reproducibility, no duplicates, honest severity. A KILL finding is dropped,
   not dressed up.
2. **Platform renderers**:
   - `shardreaper report <dir>` — client deliverable (chains, severity, ATT&CK)
   - `shardreaper report <dir> --platform h1` — HackerOne: weakness/severity/
     summary/steps/impact per finding
   - `shardreaper report <dir> --platform bugcrowd` — VRT-mapped
   - `shardreaper report <dir> --platform intigriti` — impact-first
3. **Evidence hygiene**: strip operator PII, session cookies, internal IPs
   and victim data from every capture before it enters the report. Screenshot
   the effect, not your tooling.
4. **Chain, don't checklist**: the report sells the attack path — Initial
   Access → ... → Impact. Severity is the chain's severity.

## Rules

- Findings killed by the gate are not re-written to pass — fix the evidence.
- The audit ledger is the report's backbone: every claim maps to a logged action.
