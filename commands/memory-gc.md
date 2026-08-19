---
name: memory-gc
description: Inspect or rotate the cross-engagement memory ledger (findings.jsonl, negatives.jsonl, notes.jsonl). Caps file size and keeps N rotated backups. Usage: /memory-gc [--rotate] [--purge-backups] [--max-mb N]
---

# /memory-gc — keep the resume lean

## Usage

```
shardreaper memory-gc                      # report sizes only
shardreaper memory-gc --rotate             # rotate files above 10 MB (default cap)
shardreaper memory-gc --rotate --max-mb 5  # custom cap
shardreaper memory-gc --purge-backups      # delete .1/.2/.3 backups
shardreaper memory-gc --dir <path>         # non-default ledger dir
```

Ledger location: `data/memory/` inside the project (override `SHARDREAPER_MEMORY_DIR`).
