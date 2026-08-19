---
name: shardreaper-web3
description: Web3 audit — token contracts, rug-pull vectors, DeFi attack surface. Static rug-vector scan (hidden mint, honeypot sell blocks, fee manipulation, fake renounce, upgradeable proxies, reentrancy, unlimited allowances; Solana equivalents) plus the corpus's blockchain playbooks for deep review. Use when the operator hands you a contract, token, or protocol.
---

# ShardReaper Web3 Audit — Find the Rug Before It Pulls

## Doctrine

Every token is a potential rug until the code proves otherwise. Grep the kill
signals first, then read the economics, then the access control. Static
scanning costs nothing and catches the majority of scams.

## Workflow

1. **Kill-signal scan**: `shardreaper token-scan <contract_or_dir>
   [--recursive] [--chain evm|solana] [--output report.json]` — checks:
   - hidden mint / re-armed mint · fake renounce · honeypot sell blocks
   - fee manipulation (setFee without caps, >25%) · upgradeable proxies
   - authority retention (mint/freeze/transfer powers) · unlimited approvals
   - reentrancy (`call.value` without guards) · selfdestruct · rug functions
   - Solana: mint/freeze authority not renounced, transfer hooks, fee abuse
2. **Corpus playbooks**: `shardreaper kb "smart contract audit vulnerability"`
   and `shardreaper kb "<protocol/token> exploit"` — the blockchain corpus
   carries the deep writeups.
3. **Read the economics**: fee math, bonding curves, LP locks, vesting —
   every money path is attack surface.
4. **Access control**: owner powers, multisig, timelocks, upgrade keys. Who
   can pull the rug — and does the code let them?

## Reporting

Every hit carries severity + the offending line + verdict. Map to the
platform's class for the report; include the exact code and the economic
impact in dollar terms where possible.
