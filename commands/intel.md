---
name: intel
description: Tech-stack → CVE/playbook intel from the offline corpus. Maps every discovered technology to its attack playbooks and known exploit patterns. Usage: /intel <dir> [query]
---

# /intel — know the stack, know the kill

## What it does

1. Collects the tech stack from recon (server, framework, cookies, banners).
2. Queries the corpus per technology: `<tech> cve exploit vulnerability`.
3. Returns ranked playbooks with exact paths; an extra `query` sharpens it.

## Usage

```
shardreaper intel eng/
shardreaper intel eng/ "springboot actuator rce"
```

With a brain configured, ask it to prioritize: `shardreaper ask "rank these for eng/"`.
