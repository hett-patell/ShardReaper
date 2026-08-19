# Security Policy — Authorized Use

## Supported use

ShardReaper is an adversarial-simulation tool. It is for assets you **own** or
have **written authorization to assess**:

- signed penetration-testing or red-team engagements
- bug-bounty programs, strictly on their in-scope assets
- CTF challenges and training platforms
- your own infrastructure and labs

## The scope gate

Authorization is enforced in code, not by judgment:

- `scope.py` is the gate every action passes through — DNS lookups, port
  probes, HTTP requests, and test execution included.
- **Default deny**: anything not matching an in-scope rule is rejected.
- **Deny wins**: an out-of-scope match excludes a target even when in-scope
  rules also match.
- `shardreaper scope <target> --scope <file>` re-checks any target before it
  is touched; a non-zero exit blocks automation.

## Explicitly excluded

- Using ShardReaper against any system without authorization.
- Denial-of-service beyond what an engagement explicitly permits.
- Mass-targeting or scanning infrastructure you do not own.
- Ransomware, wiper, or destructive payloads.
- Exfiltrating data that is not an authorized engagement objective.

Anything outside the operator's scope is never touched — even to "prove" a
finding. Adapt the technique or drop it.

## Reporting problems

If you find a bug in ShardReaper itself, open an issue in the repository with
the reproduction steps. Please do not demonstrate the bug against systems
you do not own.
