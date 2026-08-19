---
name: validate
description: Full pre-submission validation — 7-Question Gate + always-rejected class list + 4 pre-submission checks. Kills weak findings before any report writing. Usage: /validate <dir> [finding ids] [--yes]
---

# /validate — full validation before the report

## Pipeline

1. **7-Question Gate** — one wrong answer kills it (see `/triage`)
2. **Always-rejected list** — self-XSS, header-only findings, version
   disclosure alone, SPF/DMARC alone, clickjacking without impact, and the
   rest — killed on sight, no questions asked
3. **4 pre-submission checks** — demonstrable right now, accepted impact
   class, evidence hygiene, honest severity

## Usage

```
shardreaper validate eng/            # interactive gate
shardreaper validate eng/ --yes      # non-interactive (pipelines)
shardreaper validate eng/ F001 F002  # specific findings
```

PASS = write the report. KILL = move on — the finding is recorded as killed
and platform reports skip it automatically.
