---
name: shardreaper-evasion
description: DEFENSE EVASION phase — operate under their noses. AMSI/ETW bypass, obfuscation, AV/EDR evasion, living off the land, log tampering, privilege-aware execution. Corpus playbooks (HackTricks evasion, ired.team defense-evasion, Atomic T1562/T1070/T1027 families) + weapons (veil, donut, macro_pack). Use in EVERY phase from the first touch — assume detection.
---

# ShardReaper Defense Evasion — Operate Under Their Noses

## Doctrine

Assume the blue team is watching everything, always. Every artifact you avoid creating is an advantage. Stealth is not a phase — it is the way every phase runs.

## Workflow

1. **Corpus first**: `shardreaper kb "defense evasion amsi bypass obfuscation"` — ired.team's `defense-evasion/` has the deep writeups.
2. **Rack selection**: `shardreaper atomic select "defense evasion"` — T1562 (impair defenses), T1070 (indicator removal), T1027 (obfuscated files), T1218 (signed binary proxy), T1055 (process injection).
3. **Weapons**: `shardreaper weapons defense-evasion` — veil, donut, macro_pack, and the process-injection writeups in the corpus.
4. **Apply per platform**:
   - Windows: AMSI bypass before ANY PowerShell, ETW patching, obfuscated payloads (donut → shellcode), signed-binary proxies (rundll32, msiexec, regsvr32 — T1218), process injection (T1055), unhooking, living-off-the-land binaries.
   - Linux: no file drops (in-memory exec), renamed tools, `LD_PRELOAD`, history hygiene, unset logging env vars.
   - Network: encrypt C2 (HTTPS/DNS), mimic legit traffic, avoid scanning patterns.
5. **Before every action ask**: what artifact does this create, and how do I remove it? Cleanup commands for every atomic test are available (`shardreaper atomic run --cleanup`).

## OPSEC checklist

- [ ] AMSI/ETW handled before scripted payloads
- [ ] Payloads obfuscated / in-memory where possible
- [ ] Dropped files cleaned after use
- [ ] Logs reviewed and scrubbed within operator rules
- [ ] C2 traffic blends with baseline

## Handoff

Evasion keeps every other phase alive: persist → harvest → move → exfil, all under the noise floor.
