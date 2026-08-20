---
name: watchdog
description: Transport watchdog — auto-reconnect on tunnel failure + target re-validation after infrastructure churn, so a redeploy costs replay, not re-discovery. Usage: /watchdog <dir> [--reconnect CMD] [--interval 30]
---

# /watchdog

Infrastructure churn is ASSUMED, not hoped away. VPN drops and target
redeploys cost the whole clock when they are treated as accidents. This
command loops: healthcheck → reconnect on failure → re-validate every
known target (resolve, known ports, HTTP status), then repeats.

## Usage

```
/shardreaper watchdog eng --reconnect "systemctl restart openvpn@lab" --interval 30
/shardreaper watchdog eng --once          # single round
```

- `--reconnect CMD` — the operator's tunnel-recovery command; run
  automatically when the transport verdict goes down
- re-validation reports per host: addresses, ports up/down, URLs answering
  — a redeploy to a new IP shows up as a changed surface, not a mystery
- per-phase checkpoints (engine) mean the recovered run RE-EXECUTES the
  chain instead of re-discovering it
