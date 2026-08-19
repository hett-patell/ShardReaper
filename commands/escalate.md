---
name: escalate
description: Privilege escalation + persistence tactical phase — corpus playbooks, atomic rack, and weapons for raising and keeping access. Usage: /escalate <engagement-dir>
---

# /escalate — privilege escalation & persistence

Low privilege is a starting position. Root/domain admin is the state. And
whatever you take, you keep.

## What it does

Pulls the corpus playbooks (HackTricks + ired.team), selects the Atomic rack
tests, and lists the weapons for both phases:

```
redagent run eng --phases escalate     # privesc: sudo/setuid, tokens, services, kernel
redagent run eng --phases persist      # persistence: cron/systemd/registry/tasks/WMI
```

## Chain

1. Enumerate (LinPEAS/WinPEAS/PowerUp — see weapons rack)
2. Exploit the classic misconfigs (unquoted paths, weak perms, sudo, tokens)
3. Verify with evidence (`id`, `whoami /priv`)
4. Install redundant persistence from the first foothold
5. Test that persistence survives reboot — decoration is not persistence
