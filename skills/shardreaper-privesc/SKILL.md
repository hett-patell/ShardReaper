---
name: shardreaper-privesc
description: PRIVILEGE ESCALATION phase — take everything from everyone. Kernel exploits, sudo/setuid, weak service permissions, unquoted paths, tokens, DLL hijacking, cron, PATH hijacking, container escapes. Corpus has full playbooks (HackTricks privesc, ired.team privesc, PEASS/LinPEAS/WinPEAS in the weapons rack). Use after a foothold whenever the operator wants domain/root access.
---

# ShardReaper Privilege Escalation — Take Everything

## Doctrine

Low privilege is a starting position, not a state. The goal is root/domain admin — everything else is a step. Enumerate first, exploit second, escalate until there is nothing left to take.

## Workflow

1. **Corpus first**: `shardreaper kb "privilege escalation enumeration"` — the corpus returns the full checklists and exploit writeups.
2. **Enumeration weapons**: `shardreaper weapons privilege-escalation` — LinPEAS / WinPEAS (PEASS-ng), PowerUp, Seatbelt. Run them; read everything they print.
3. **Rack selection**: `shardreaper atomic select "privilege escalation" --platform <linux|windows>`.
4. **Exploit the classics, in order**:
   - Linux: sudo misconfigs (`sudo -l`), SUID binaries, writable PATH, cron jobs, weak service perms, kernel CVEs, capabilities, Docker group / container escape.
   - Windows: unquoted service paths, weak service permissions, AlwaysInstallElevated, token impersonation (SeImpersonate → potato family), service binaries writable by users, UAC bypass, kernel CVEs, AD path: kerberoastable accounts, ACL abuse.
   - Web/cloud: exposed actuator/env, cloud metadata (169.254.169.254), IAM role abuse, container escape via privileged pods.
5. **Chain everything**: every new privilege opens new enumeration (Seatbelt again as SYSTEM), every new credential opens new techniques.
6. **Verify**: each escalation step gets evidence — `id`, `whoami /priv`, registry/proc proof. Log technique ids (T1068, T1134, T1548...).

## Handoff

Root/domain admin → credential harvest (mimikatz, secretsdump, domain dump) → lateral movement with full rights → exfiltration of the crown jewels.
