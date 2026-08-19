---
name: shardreaper-lateral
description: LATERAL MOVEMENT phase — spread through the estate. SMB/WinRM/PSExec, pass-the-hash, RDP, SSH, VNC, MSSQL xp_cmdshell, cloud role pivots. Corpus playbooks (HackTricks lateral movement, ired.team lateral-movement) + Atomic rack + impacket/evil-winrm/NetExec weapons. Use once you hold credentials or privileged access.
---

# ShardReaper Lateral Movement — Spread Through the Estate

## Doctrine

One box is a foothold. The network is the target. Move with purpose: find the high-value systems (DC, file servers, dev boxes, backups) and land on them with the best credentials you hold.

## Workflow

1. **Corpus first**: `shardreaper kb "lateral movement psexec winrm pass the hash"`.
2. **Rack selection**: `shardreaper atomic select "lateral movement"` — plus T1021 family (Remote Services: T1021.001 RDP, .002 SMB, .003 WinRM, .004 SSH, .005 VNC).
3. **Weapons**: `shardreaper weapons lateral-movement` — impacket (psexec/wmiexec/smbexec), evil-winrm, NetExec/CrackMapExec, chisel/ligolo for pivots.
4. **Move with the best tool per protocol**:
   - SMB: impacket psexec / NetExec with pass-the-hash (T1550.002).
   - WinRM: evil-winrm (5985/5986).
   - RDP: restricted admin mode + hash (T1021.001).
   - SSH: harvested keys, password reuse.
   - SQL: MSSQL xp_cmdshell / CLR (T1059.001), linked servers.
   - Cloud: metadata/role pivots, SSRF to IAM, service principal reuse.
5. **Pivot when blocked**: SOCKS tunnels (chisel/ligolo) through the box you own; route scans and exploits through it. Never attack the next host directly from your own machine.
6. **Repeat**: enumerate the new host (Seatbelt/enum), harvest its creds, move again. Depth: DC or crown-jewel asset = objective complete.

## OPSEC

- Living off the land: WinRM and scheduled tasks are noisier than SMB named pipes — choose by target.
- Clean up remote artifacts; delete dropped files and event-visible scripts when the operator's rules allow.

## Handoff

Estate mapped → collection on high-value hosts → exfiltration of the objective data.
