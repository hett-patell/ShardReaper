---
name: shardreaper-osint
description: OSINT + scope-expansion discipline. Passive subdomain discovery (certificate transparency, subfinder, assetfinder), scope filtering, liveness probing, and surface growth BEFORE active testing. Use at the start of every domain engagement and whenever the authorized footprint must grow.
---

# ShardReaper OSINT — Grow the Authorized Footprint First

## Doctrine

The first move on a domain is discovering the footprint, not jumping at the
apex page. Passive enumeration costs the target nothing and reveals doors
active scanning never sees.

## Workflow

1. **Scope gate first**: every discovered host must pass
   `shardreaper scope <host> --scope <dir>/scope.json`. Discovery without
   authorization means nothing.
2. **Passive expansion**: `shardreaper osint <domain> --in-scope <pattern>`
   — unions certificate transparency (crt.sh), subfinder, assetfinder, then
   probes liveness. Deterministic, offline-first.
3. **Fold into recon**: the engine runs OSINT expansion automatically before
   the active sweep (`--no-osint` disables).
4. **Kill stale surface**: hosts that don't resolve don't get touched. Every
   live in-scope host becomes a recon seed.

## Rules

- Passive only for discovery — active touches wait for the sweep, gated.
- Subdomain wildcard results still pass the scope gate individually.
- Log every discovery to the ledger; the operator owns the scope decisions.
