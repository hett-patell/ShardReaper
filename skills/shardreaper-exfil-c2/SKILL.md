---
name: shardreaper-exfil-c2
description: EXFILTRATION & C2 phase — take the data and keep the channel. Locate the crown jewels (collection), stage them, and exfiltrate over approved channels; stand up C2 (Sliver/Mythic/Empire/dnscat2/chisel) and tunnel everything. Corpus playbooks (ired.team exfiltration, Atomic T1041/T1048/T1567) + weapons rack. Use when the objective is data, or when the operator orders the network held.
---

# ShardReaper Exfiltration & C2 — Take the Data, Keep the Channel

## Doctrine

The objective is data. Find it, collect it, and move it out on a channel that survives. C2 is the lifeline: if the operator loses the channel, the operation is over — so build redundancy.

## Workflow

### Collection (T1005/T1039/T1119)
1. Locate the crown jewels: document shares, database backups, source repos, mail stores, cloud storage buckets. `shardreaper kb "collection document share database backup"` for playbooks.
2. Stage on the box you own: archive quietly (native compression tools), keep staging on-disk minimal.

### Exfiltration
3. Choose the channel that fits the network:
   - Web/HTTPS: `shardreaper kb "exfiltration http"` — T1041, T1567 (web service), T1048 (alternative protocol).
   - DNS: DNSExfiltrator/dnscat2 — slow but survives most egress filters (T1048.003).
   - Encrypted tunnels: chisel/ligolo over 443 — looks like HTTPS, carries everything.
4. Size it right: chunk, encrypt (the target's own crypto), verify integrity per chunk, remove staging artifacts after each transfer.

### C2 (T1071/T1105/T1573)
5. Stand up the framework: `shardreaper weapons c2` — Sliver (recommended: modern, cross-platform), Mythic, Empire, or dnscat2 for pure-DNS. 
6. Redundancy: two channels minimum — primary HTTPS, fallback DNS. Heartbeat-based reconnection. Implants that survive reboots (see shardreaper-persist).
7. Tunnels for movement: chisel/ligolo SOCKS through owned boxes — never let operator traffic touch targets directly.

## OPSEC

- Encrypt everything in transit; blend with TLS/legit services.
- DNS exfil: keep queries under thresholds, use domain-fronting where allowed.
- Clean staging dirs and archives after transfer. Assume DLP is watching size and pattern — mimic normal usage.

## Handoff

Data delivered to the operator → report (chains + evidence) → debrief: every technique, every artifact, every credential, mapped to ATT&CK.
