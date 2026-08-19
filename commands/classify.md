---
name: classify
description: Map a URL or tech string to the attack classes and playbooks that apply — GraphQL, OAuth, JWT, upload, SharePoint, Spring/Actuator, M365, VPN appliances, and more. Usage: /classify <url|tech...>
---

# /classify — what is this surface, and how do I kill it

## Usage

```
shardreaper classify https://api.example.com/graphql
shardreaper classify "springboot actuator jwt"
shardreaper classify https://login.example.com/oauth/authorize
```

Every signature returns the ranked playbooks (with exact corpus paths) for
that class. Pairs with `/map` (full arsenal) and `/intel` (CVE layer).
