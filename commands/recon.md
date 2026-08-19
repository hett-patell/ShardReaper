---
name: recon
description: Sweep the authorized surface — DNS, ports, banners, TLS, HTTP fingerprinting, sensitive paths, CORS, headers. Usage: /recon <engagement-dir>
---

# /recon

Map everything the operator authorized. Sweep wide, then deep. Nothing is
ever contacted without passing the scope gate first.

## What runs (deterministic, stdlib-first)

1. DNS: resolution, AXFR zone-transfer attempts, subdomain brute (in-scope filtered)
2. Ports: TCP connect sweep (top 100), banner grabs, TLS cert inspection
3. HTTP: status/title/server/tech per web port; ~30 sensitive paths probed
   (`.git/HEAD`, `.env`, backups, admin panels, actuator, swagger, graphql...)
4. CORS misconfig check; missing security-header audit

## Usage

```
/recon eng
/redagent recon --host 10.0.0.5 --in-scope 10.0.0.0/24   # ad-hoc single host
```

Every discovery lands in `state.json` + the ledger. Exposed sensitive files
become HIGH findings immediately. Follow with `/plan`.
