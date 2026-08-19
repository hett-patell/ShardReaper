---
name: shardreaper-recon
description: RECON phase — map everything the operator authorized. DNS resolution, zone-transfer checks, subdomain brute, port sweep with banners, TLS cert inspection, HTTP fingerprinting, tech detection, sensitive-path probing, CORS check, security-header audit. Use at the start of every engagement and whenever the surface must grow. Consult the corpus for enumeration techniques first.
---

# ShardReaper Recon — Map Everything

## Doctrine

Recon is never "done" — the surface grows until the operator says stop. Sweep wide, then deep. Everything you find expands the attack plan.

## Workflow

1. **Confirm scope**: `shardreaper scope <seed> --scope <dir>/scope.json` — every target must pass; nothing else is ever touched.
2. **Corpus first**: `shardreaper kb "recon enumeration dns subdomain port scan"` — pick 3-5 techniques from the hits.
3. **Run the sweep**: `shardreaper run <dir> --phases recon` (or ad-hoc `shardreaper recon --host <host> --in-scope <pattern>`).
4. **Weapons**: `shardreaper weapons recon --limit 20` — Amass, subfinder, dnsrecon, ffuf, gobuster, nuclei, masscan, WitnessMe, SpiderFoot, cloud_enum, S3Scanner...
5. **External tools when installed**: nmap (`-Pn -sV --open`), nuclei, ffuf. ShardReaper wraps them automatically.
6. **Analyze**: `shardreaper run <dir> --phases analyze` — service hints are extracted and KB references attached automatically.

## What the sweep covers (deterministic, stdlib)

- DNS: A/AAAA resolution, AXFR zone-transfer attempts (finding if allowed), subdomain brute with the builtin wordlist (in-scope filtered)
- Ports: TCP connect sweep (top 100 by default), banner grab, TLS cert inspection on TLS ports (expired cert = finding)
- HTTP: status, title, server, tech stack, cookies; probes of ~30 sensitive paths (`.git/HEAD`, `.env`, backups, admin panels, actuator, swagger, graphql...) — exposed-file hits become HIGH findings
- CORS misconfiguration check (reflected Origin)
- Missing security headers audit (HSTS/CSP/XFO/XCTO)

## Aggression rules

- Probe every in-scope host:port that answers. Assume every port is a door.
- Chase every `200` on a sensitive path — that is a finding, not a checkbox.
- If a service banner is unknown, `shardreaper kb "<banner text>"` — the corpus knows it.
- Log everything: the ledger is the operator's audit trail.

## Handoff

Output of recon feeds `analyze` → `plan` → `attack`. Never stop at the first live host; map the whole authorized surface.
