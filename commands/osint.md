---
name: osint
description: Passive scope expansion — certificate transparency + subfinder + assetfinder, scope-filtered, liveness-probed. Usage: /osint <domain> --in-scope <pattern>
---

# /osint — grow the authorized footprint first

## Usage

```
shardreaper osint example.com --in-scope example.com
shardreaper osint example.com --in-scope '*.example.com' --max-hosts 500
```

Every discovered host still passes the scope gate before it is touched.
The engine runs this automatically before the active sweep (`--no-osint`
disables).
