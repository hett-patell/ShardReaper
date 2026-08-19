---
name: kb
description: Search the local offensive corpus (Atomic Red Team, HackTricks 916 skills, ired.team 211 writeups, BugHunter 83 skills, tool catalogs) before choosing ANY technique. Usage: /kb <query>
---

# /kb — knowledge base

The corpus is the weapon library. Consult it before every technique decision —
it indexes the full reference tree that ships beside ShardReaper.

## Usage

```
/kb golden ticket kerberos
/kb amsi bypass powershell
/kb unquoted service path escalation
/kb exposed git source disclosure exploit
```

## Under the hood

```
shardreaper kb <query> [--limit N] [--corpus <hacktricks|ired|bughunter>]
shardreaper kb-open <query>          # exact path of the best hit
shardreaper atomic list --search <q> # executable tests for the technique
shardreaper weapons <query>          # the tool that does it
```

## Rules

- Technique selection without a corpus lookup is guesswork — don't.
- Open the best hit and follow its playbook. Evidence over theory.
