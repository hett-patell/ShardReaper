# /webattack — HTTP exploitation primitives

Fire the engine-native web exploit families against the engagement's
discovered URLs: auth-bypass matrix, verb tampering, IDOR differential,
host-header injection, HPP — plus the offline JWT audit and forgery replay.

## Engine phase

```
shardreaper run eng/ --phases webattack            # dry-run: renders the probe matrix
shardreaper run eng/ --phases webattack --go       # fire it
```

The matrix is built from recon state, per URL:

| URL shape | Families fired |
|---|---|
| every in-scope URL | `verb-tamper` |
| baseline 401/403 | `auth-bypass` |
| numeric id in path/query, or 2+ contexts | `idor` |
| query params present | `hpp` |
| every origin (once) | `host-header` |

Every (url, family) pair is a tracked hypothesis (budget 2, no-evidence
cutoff 2): hits become evidence + findings; empty sweeps spend budget and
tombstone, so `pickup` never re-wastes a dead probe. Hits land as findings
with severity (auth bypass on an adminish path is CRITICAL), the exact
request mutation, and the baseline→observed diff.

Dry-run writes the full matrix to `notes` (`webattack-plan`) and fires
nothing. The JWT offline audit always runs — it touches no network.

## Authenticated contexts

IDOR context-differential compares what `anon` sees against authenticated
jars. Operator-seeded contexts live in state as `http_contexts`
(e.g. `["user:victim"]`) — the origin-bound transport keeps their cookies
in isolated per-(origin, context) jars (lesson 16).

## JWT

```
shardreaper jwt <token> [--secret S] [--forge]
shardreaper jwt --file token.txt
```

Offline audit: alg=none, missing exp, kid/jku/x5u injection points,
RS/ES→HS confusion candidates, and an HMAC secret brute against the
built-in common-secret list. A brute-forced secret is a HIGH finding
offline; with `--go`, the phase replays alg=none forgeries and re-signed
tokens at every denied endpoint — an accepted forgery is CRITICAL, proven.

## Field notes

* Baseline first, always. Every verdict is a diff against the untouched
  response — never an absolute guess.
* One proven IDOR neighbour is enough — report, don't spray.
* Host-header probes carry unique canary tokens on `.invalid` — a hit is
  the canary reflected in body or Location, nothing else.
