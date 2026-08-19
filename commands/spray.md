---
name: spray
description: Fire every held credential (passwords, SA tokens, JWTs) against every authenticated surface — kubelet, apiserver, registry, SSH, docker socket — with all protocol variants. Usage: /spray <engagement-dir>
---

# /spray

A harvested credential is ammunition, not a trophy. This command loads the
engagement credential set (plus the findings ledger and any `--creds` files)
and fires it at every authenticated surface the recon found — because the
credential you found in a web app is the same credential the kubelet will
accept on port 10250.

## Surfaces

- **kubelet** `:10250` — `/pods`, `/runningpods/` (the canonical miss)
- **apiserver** `:6443` — `/api/v1/namespaces`, `/version`
- **registry** `:5000` — `/v2/`
- **docker socket** — local `/var/run/docker.sock` + remote `:2375`
- **SSH** `:22` — password login via sshpass when present
- **discovered HTTP URLs** — from recon state

## Protocol variants per credential

| type       | variants fired                                      |
|------------|-----------------------------------------------------|
| sa-token   | `Authorization: Bearer`                             |
| jwt        | Bearer, `X-Api-Key`                                 |
| password   | Basic (user candidates), cookie, SSH login          |
| api-key    | `X-Api-Key`, Bearer                                 |
| cookie     | `Cookie: session=`                                  |

## Authn/authz differential (enforced)

- **401** → automatically retried with EVERY held credential.
- **400** → malformed/websocket-upgrade (not a denial).
- **403 + websocket/subprotocol body** → protocol mismatch — never RBAC.
- **403 + forbidden/user markers** → RBAC denial — proof the credential AUTHENTICATED.
- **404** → surface absent; **500** → server error, retry-later.

## Usage

```
/shardreaper spray eng [--creds creds.json] [--no-ssh] [--timeout 6]
```

Hits are logged as findings (severity by surface: kubelet/apiserver/SSH =
critical) with evidence, written to `spray.json`, and added to the
engagement credential set so nothing is ever re-sprayed. This phase also
runs automatically in `run --phases ...,harvest,spray,...`.
