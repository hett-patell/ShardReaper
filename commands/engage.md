---
name: engage
description: Start an engagement — the operator authorizes scope (the ONLY gate), seeds, and objective. Usage: /engage <name> --seeds <url> --in-scope <pattern> [--out-of-scope <pattern>]
---

# /engage

The mission starts here. The operator defines the rules — everything else is
aggression.

## Usage

```
/engage demo --seeds http://10.0.0.5 --in-scope 10.0.0.0/24 --out-of-scope 10.0.0.10
/engage webapp --seeds https://app.corp --in-scope app.corp --in-scope '*.corp'
```

Creates the engagement folder with `scope.json` (in/out patterns + seeds) and
the audit ledger. Scope is enforced in code from this moment on — deny by
default, deny wins.

## Pattern forms

- `example.com` → apex + any subdomain
- `*.example.com` → any subdomain (not the bare apex)
- `api.example.com` → that exact host
- `10.0.0.0/8` → any IP in the CIDR
- `re:^staging[0-9]+\.example\.com$` → regex
- `host:443`, `host:1-65535` → port-bound scope

## Rules

- The operator's scope is the only law. Anything inside: full aggression.
- An empty in-scope list = everything rejected. Fill it deliberately.
