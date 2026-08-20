---
name: sink
description: Sink-contract gate — prove the render/exec path (source read or self-test marker) BEFORE building any injection payload. Usage: /sink <dir> --kind ssti|template|xss|ssrf|rce-echo|deser [--source file]
---

# /sink

No payload before the contract. For every injection theory the cheapest
oracle must answer first:

1. **Source first** — read the render path from public source / templates /
   entrypoint. A raw-string/escape path DISQUALIFIES the sink; a
   render_template/eval/unserialize path PROVES it. Source evidence
   outranks every black-box guess.
2. **Marker self-test** — `{{7*7}}` → expect `49` (and the per-kind marker
   table: `${7*7}`, `#{7*7}`, `<%= 7*7 %>`, magic strings).

## Usage

```
/shardreaper sink eng --kind ssti --source app.py    # source oracle
/shardreaper sink eng --kind ssti                    # show markers + status
```

The attack phase refuses payload construction for any sink without a
proven contract (`exploit_allowed` gate) — the analyze phase records
unverified contracts for every hinted sink automatically. One source read
kills hours of blind SSTI/template/deserialization payloading.
