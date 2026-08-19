---
name: autopilot
description: Autonomous loop from the current phase to report, with configurable checkpoints. Usage: /autopilot <dir> [--paranoid|--normal|--yolo] [--go]
---

# /autopilot — hands-off, gates on

Drives the engagement from wherever it stopped to REPORT.md. Scope stays
code-enforced in every phase, every mode.

## Usage

```
shardreaper autopilot eng/                    # --paranoid: checkpoint after each phase
shardreaper autopilot eng/ --normal           # checkpoint after attack + before report
shardreaper autopilot eng/ --yolo             # no checkpoints
shardreaper autopilot eng/ --yes              # non-interactive (pipelines)
shardreaper autopilot eng/ --phases plan,attack,report
```

## Checkpoints

- **paranoid** — operator confirms after every phase
- **normal** — confirm after attack, before report
- **yolo** — runs through; report is still deterministic, gate still on

Non-TTY stdin skips prompts automatically.
