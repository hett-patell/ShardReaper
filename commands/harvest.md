---
name: harvest
description: Credential access + lateral movement tactical phase — take every secret, spread through the estate. Usage: /harvest <engagement-dir>
---

# /harvest — credentials & movement

Credentials are the currency of the network. Harvest everything, then spend
it to spread everywhere.

## What it does

```
shardreaper run eng --phases harvest    # lsass, SAM, tickets, stores, configs, cloud
shardreaper run eng --phases move       # SMB/WinRM/RDP/SSH, pass-the-hash, pivots
```

## Harvest order

1. Memory (lsass) → stores (SAM/DPAPI) → network (responder, Kerberos tickets)
2. Disk/config (`.env`, web.config, git history, cloud creds, SSH keys)
3. Crack offline (hashcat/john), verify each credential at the next door

## Movement

- impacket psexec/wmiexec, evil-winrm, NetExec with pass-the-hash
- Pivot through owned boxes (chisel/ligolo) — never attack the estate from
  your own machine
- Repeat: enumerate → harvest → move → until the DC / crown jewels fall

## Rule

One credential often opens the whole estate. Test every harvest. Log provenance.
