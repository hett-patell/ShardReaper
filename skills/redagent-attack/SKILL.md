---
name: redagent-attack
description: ATTACK phase — initial access and execution. Turn recon findings into footholds: exposed paths, weak auth, vulnerable services, web exploitation classes. Select ATT&CK tests from the local Atomic Red Team rack, render and execute them (dry-run by default, --go executes), and chain every win into the next step. Use when a target has been mapped and the operator orders the attack.
---

# RedAgent Attack — Take the Foothold

## Doctrine

Recon told you where the doors are. Now kick them in — all of them, in parallel, in order of impact. First foothold → execution → persistence thinking from second one.

## Workflow

1. **Scope re-check on every target**: `redagent scope <host> --scope <dir>/scope.json`. Always.
2. **Plan first**: `redagent run <dir> --phases plan` — the engine ranks attack items by severity and maps them to techniques + atomic tests. With a brain configured (`REDAGENT_LLM_*`), it also ranks full attack chains.
3. **Corpus for the specific vector**: `redagent kb "<vector> exploit technique"` — e.g. "path traversal", "sql injection", "default credentials", "exposed git", "deserialization".
4. **Fire the rack**: `redagent atomic select --technique <TID>` → `redagent atomic run --technique <TID> --index <n> [--go]`. Dry-run first to see the exact commands; `--go` only when the operator authorized execution.
5. **Exploit primitives (stdlib, in engine)**: for exposed `.git`/`.env`/backups — dump contents, extract secrets; for web apps — path traversal probes, verb tampering, auth-bypass checks, default-credential checks on admin panels.
6. **Weapons for the heavy lifting**: `redagent weapons attack --phase initial-access` — sqlmap, hydra, kerbrute, metasploit, macro_pack...

## Chain rules

- Every confirmed finding is a door: credentials → harvest, `.git` leak → source review → more secrets, web shell → execution → persistence.
- ATT&CK mapping always: Initial Access (T1133/T1190/T1566...), Execution (T1059/T1204...). Log the technique id on every action.
- Do not stop at the first shell. The operator wants the domain, not a demo.

## Evidence doctrine

A finding without evidence is a rumor. Capture: request/response pairs, the exact command, the output proving impact. `redagent status <dir>` shows confirmed findings; `redagent report <dir>` ships them.

## Handoff

Foothold → `redagent-persist` (keep it) → `redagent-privesc` (raise it) → `redagent-credharvest` (take everything).
