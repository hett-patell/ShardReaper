---
name: priv
description: Privileged-consumer dataflow audit — cron/systemd-timer inventory, input-source tracing, path-escape canaries. The universal Linux root path. Usage: /priv [--canary name] [--json]
---

# /priv

Root escalation is a dataflow problem: a ROOT-run periodic consumer reads
attacker-influenceable input through a path-join or command-construction
bug. This command inventories the consumers, traces their inputs, and
generates the path-contract canaries that trip them.

## What runs

1. **Inventory** — /etc/crontab, /etc/cron.d, cron.{daily,hourly,weekly,
   monthly}, anacrontab, user crontabs, systemd timers (`list-timers`).
2. **Trace** — which jobs touch attacker-influenceable paths (/tmp,
   /var/www, uploads, repo checkouts, logs) and which dangerous ops they
   use (path-join with vars, `$()`, backticks, tar wildcards, find -exec,
   git hooks, interpreter launches).
3. **Canaries** — the path-contract test corpus: absolute paths, `..`
   components, separators, `;id`, `$(id)`, globs, suffixes. Feed these as
   filenames/content to the consumer and watch which one it resolves.

## Usage

```
/shardreaper priv [--canary payload] [--json]
```

Run it on the box (or point the engine's exec transport at it) the moment
a low-privilege foothold exists — the ranked `risks` list is the ordered
escalation queue. Never guess a cron job's behavior: trace it, then test
its path contract with canary names.
