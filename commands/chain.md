---
name: chain
description: Build an A→B→C exploit chain from a confirmed finding for maximum impact. Usage: /chain <dir> --finding F001 | --class idor
---

# /chain — one finding is a step, not a result

## Known chain patterns

- IDOR → ATO → mass data · exposed .git → source → hardcoded secrets → RCE
- SSRF → cloud metadata → IAM keys · open redirect → OAuth token theft
- XSS → session theft → ATO · SQLi → DB dump → credential reuse
- weak credentials → password reuse → lateral movement
- CORS → cross-origin data theft → ATO

## Usage

```
shardreaper chain eng/ --finding F001
shardreaper chain eng/ --class idor
```

Every step returns the playbook path to execute it. Chain severity, not
single-finding severity, is what the report sells.
