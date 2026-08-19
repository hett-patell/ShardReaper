---
name: web3-audit
description: Full token/protocol audit — rug-vector scan + corpus playbooks + economics + access control. Usage: /web3-audit <path|dir> [--recursive]
---

# /web3-audit — the full review

## Workflow

1. `shardreaper token-scan <path> --recursive` — kill signals first
2. `shardreaper kb "smart contract audit <protocol/type>"` — corpus playbooks
3. Read the economics: fee math, bonding curves, LP locks, vesting
4. Access control: owner powers, multisig, timelocks, upgrade keys — who can
   pull the rug, and does the code let them?

## Rules

- A verified contract with hidden-mint capability is a critical finding, not a footnote.
- Report economic impact in dollars: what does the vector let an attacker take?
