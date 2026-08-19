---
name: shardreaper-credharvest
description: CREDENTIAL ACCESS phase — take every secret. lsass/mimikatz, SAM/SYSTEM, Kerberos tickets (kerberoast, AS-REP roast, golden/silver), browser stores, config files, cloud credentials, SSH keys, memory. Full playbooks in the corpus (HackTricks credential access, ired.team credential dumping, Atomic T1003 family). Use after a foothold and after privilege escalation.
---

# ShardReaper Credential Harvest — Take Every Secret

## Doctrine

Credentials are the currency of the network. Harvest aggressively, verify immediately, and use them before they rotate. A harvested secret is only valuable if it opens the next door.

## Workflow

1. **Corpus first**: `shardreaper kb "credential dumping kerberos mimikatz"` — ired.team's `credential-access-and-credential-dumping/` is a full curriculum.
2. **Rack selection**: `shardreaper atomic select --technique T1003` (OS Credential Dumping — 8 sub-techniques), plus `kerberoast` keyword search.
3. **Weapons**: `shardreaper weapons credential-access` — mimikatz, Rubeus, LaZagne, responder, hashcat, john...
4. **Harvest in this order**:
   - Memory: lsass dump (mimikatz sekurlsa::logonpasswords), task manager / procdump.
   - Stores: SAM/SYSTEM hive, DPAPI, browser creds, WiFi profiles, vault.
   - Network: responder/LLMNR poisoning, SMB relay, Kerberos tickets (kerberoast T1558.003, AS-REP roast T1558.004, golden T1558.001, silver T1558.002).
   - Disk/config: .env, web.config, appsettings, git history (gitleaks/truffleHog), cloud creds (~/.aws, azure profiles, service principals), SSH keys, backup files.
5. **Crack offline**: hashcat/john on harvested hashes (`shardreaper weapons credential-access`).
6. **Use them**: test each credential against the next door (WinRM, SMB, SSH, web logins, cloud consoles). Log every credential's provenance — the operator needs to know where each one came from.

## OPSEC

- Harvest on the target, crack and analyze offline. Minimize what you write to disk.
- Note password reuse: one credential often opens the whole estate.

## Handoff

Credentials → lateral movement (pass-the-hash, WinRM, PSExec) → deeper collection → exfiltration.
