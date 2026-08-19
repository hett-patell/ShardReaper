---
name: map
description: Route a class/technique to its full arsenal — corpus playbooks + atomic tests + weapons, in one shot. Usage: /map <query>
---

# /map — one query, the whole rack

## Output

- **playbooks** — ranked corpus hits with exact paths
- **atomics** — executable ATT&CK tests (strict name/technique matching)
- **weapons** — the tools that do it

## Usage

```
shardreaper map "kerberos golden ticket"
shardreaper map "privilege escalation linux"
```

The engine's plan/attack phases run this same routing automatically per item.
