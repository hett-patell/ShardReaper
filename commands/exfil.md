---
name: exfil
description: Exfiltration, C2 and report — take the data, hold the network, ship the report. Usage: /exfil <engagement-dir>
---

# /exfil — exfiltration, C2 & reporting

The objective is data. Find it, collect it, move it on a channel that
survives — and keep the network in your hand while you do.

## What it does

```
redagent run eng --phases evade      # AMSI/ETW bypass, obfuscation, log hygiene
redagent run eng --phases exfil      # collection + exfiltration channel selection
redagent report eng                  # render REPORT.md (chains + evidence)
redagent status eng                  # live state: findings, actions, plan
```

## Exfiltration channels (pick by egress)

- HTTPS tunnels (chisel/ligolo over 443) — carries everything
- DNS (dnscat2/DNSExfiltrator) — slow, survives strict egress
- Web services (T1567) / alternative protocols (T1048)

## C2

- Sliver / Mythic / Empire / dnscat2 — two channels minimum, implants that
  survive reboots (see persistence)
- Tunnel all operator traffic through owned boxes

## Report

Findings carry severity, class, evidence, ATT&CK mapping, and next moves.
Chains, not checklists. The report is the deliverable — the operator's
debrief is only as good as the ledger.
