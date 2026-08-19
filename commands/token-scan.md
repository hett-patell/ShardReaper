---
name: token-scan
description: Rug-pull / scam-vector audit for token contracts (EVM/Solidity + Solana/Rust). Static grep audit with severity + line evidence; slither/aderyn used when installed. Usage: /token-scan <path> [--recursive] [--chain evm|solana]
---

# /token-scan — find the rug before it pulls

## Vectors checked

- hidden mint / re-armed mint · fake renounce · honeypot sell blocks
- fee manipulation (uncapped setFee, >25%) · upgradeable proxies
- authority retention (mint/freeze/transfer powers) · unlimited approvals
- reentrancy (`call.value` without guards) · selfdestruct · rug functions
- Solana: mint/freeze authority not renounced, transfer hooks, fee abuse

## Usage

```
shardreaper token-scan contracts/Token.sol
shardreaper token-scan src/ --recursive
shardreaper token-scan programs/token/ --chain solana --recursive
shardreaper token-scan contracts/Token.sol --output findings/token.json
```

Every hit: severity + offending line + verdict. Pair with `/web3-audit`
for the full economic + access-control review.
