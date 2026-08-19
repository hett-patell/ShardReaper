---
name: remember
description: Note extra operator context on a target — technique detail, follow-up idea, environment quirk. Usage: /remember <note...> [--host H]
---

# /remember — operator notes

Capture is automatic during runs; this is for the context the engine can't see.

## Usage

```
/remember the WAF resets sessions every 10 minutes
/remember "spray only at 2 req/s" --host target.com
/remember "check the old admin panel next time" --dir eng/
```

Notes land in the memory ledger and appear in `/pickup`.
