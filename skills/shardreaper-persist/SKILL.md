---
name: shardreaper-persist
description: PERSISTENCE phase — keep every foothold. Scheduled tasks/cron, registry autorun, services, WMI/COM hijacking, SSH keys, web shells that survive. Consult the corpus (HackTricks persistence, ired.team persistence) and the Atomic Red Team persistence rack, then install redundant persistence. Use after any foothold, before privilege escalation, and whenever the operator needs the access to survive.
---

# ShardReaper Persistence — Keep What You Take

## Doctrine

A foothold you cannot keep is a failed foothold. Persistence is planned from the FIRST shell, not as an afterthought. Install redundant mechanisms: if one dies, another answers.

## Workflow

1. **Corpus first**: `shardreaper kb "persistence scheduled task registry cron autorun"` — HackTricks + ired.team have the full playbooks.
2. **Rack selection**: `shardreaper atomic select persistence --platform <linux|windows>` — pick 4-6 tests across mechanisms.
3. **Weapons**: `shardreaper weapons persistence` — PowerUp, Empire, Sliver, macro_pack...
4. **Execute per platform**:
   - Windows: registry `Run` keys, scheduled tasks, services (unquoted paths/weak perms — also a privesc vector), WMI event subscriptions, startup folder, DLL hijacks (check ired.team `persistence/`).
   - Linux: crontab, systemd units, rc.local, SSH authorized_keys, `.bashrc`/`.profile`, LD_PRELOAD, PAM backdoors (corpus has the recipes).
   - Web: web shells outside docroot reach, cron-driven re-upload, `.htaccess` tricks.
5. **Test each mechanism** — persistence that doesn't survive a reboot is decoration. Log each install with technique id.

## OPSEC

- Blend: use the target's own tooling, native binaries, legitimate paths.
- Prefer living-off-the-land over dropping files. Clean up installers.
- Assume the blue team reviews scheduled tasks and autoruns — alternate between mechanisms.

## Handoff

Persistence installed → escalate privileges → harvest credentials → move laterally with the new access.
