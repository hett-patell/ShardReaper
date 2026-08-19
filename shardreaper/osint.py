#!/usr/bin/env python3
"""
osint.py — passive OSINT / scope expansion.

The first move on a domain is discovering the in-scope footprint, not jumping
straight at the apex. Passive sources first (subfinder, assetfinder,
certificate transparency via crt.sh), then scope-filter, then liveness
probing. Everything is mechanical — no LLM in enumeration. Every discovered
host is still checked against the scope gate before it is ever touched.
"""
import json
import os
import shutil
import ssl
import subprocess
from urllib.parse import urlparse


def _run(cmd, timeout=120):
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout).stdout
    except Exception:
        return ""


def crtsh(apex, timeout=25):
    """Certificate-transparency passive subdomain discovery (crt.sh)."""
    names = set()
    try:
        ctx = ssl.create_default_context()
        import urllib.request
        req = urllib.request.Request(
            f"https://crt.sh/?q=%25.{apex}&output=json",
            headers={"User-Agent": "ShardReaper/1.0 (authorized security testing)"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
        for entry in data or []:
            for nm in str(entry.get("name_value", "")).split("\n"):
                nm = nm.strip().lower().lstrip("*.").rstrip(".")
                if nm and nm.endswith(apex.lower()):
                    names.add(nm)
    except Exception:
        pass
    return names


def enumerate_subdomains(apex, log=None):
    """Union of subfinder + assetfinder + crt.sh + the builtin wordlist brute."""
    log = log or (lambda *a, **k: None)
    subs = {apex.lower()}
    if shutil.which("subfinder"):
        out = _run(["subfinder", "-d", apex, "-silent"], 150)
        got = [x.strip().lower().rstrip(".") for x in out.splitlines() if x.strip()]
        subs.update(got)
        log(f"osint: subfinder -> {len(got)} name(s)")
    if shutil.which("assetfinder"):
        out = _run(["assetfinder", "--subs-only", apex], 90)
        got = [x.strip().lower().rstrip(".") for x in out.splitlines() if x.strip()]
        subs.update(got)
        log(f"osint: assetfinder -> +{len(got)} name(s)")
    ct = crtsh(apex)
    if ct:
        subs.update(ct)
        log(f"osint: crt.sh -> +{len(ct)} name(s)")
    return subs


def osint_expand(scope, seeds, log=None, resolve=None, max_hosts=300):
    """Passive scope expansion: discover in-scope subdomains, probe liveness.

    Returns a list of live, in-scope hosts (each already scope-checked).
    """
    log = log or (lambda *a, **k: None)
    from .recon import Recon
    r = Recon(scope, log=log)
    resolve = resolve or r.resolve
    live = []
    for seed in seeds:
        host = (urlparse(seed if "://" in seed else "//" + seed).hostname or "").lower()
        if not host or host.count(".") < 1 or host.replace(".", "").isdigit():
            continue
        if not scope.in_scope_host(host):
            log(f"osint: skip {host} (out of scope)", "warn")
            continue
        subs = sorted(enumerate_subdomains(host, log))[:max_hosts]
        for sub in subs:
            if not scope.in_scope_host(sub):
                continue
            if sub in (s for s in live):
                continue
            if resolve(sub):
                live.append(sub)
        log(f"osint: {host} -> {len(live)} live in-scope host(s)")
    return live


def cli_osint(args):
    from .scope import Scope
    from .recon import Recon
    scope = Scope(args.in_scope or [], [], name="osint")
    live = osint_expand(scope, [args.domain], log=lambda m, l="info": print(f"[osint] {m}"))
    print(f"\nlive in-scope hosts: {len(live)}")
    for h in live[:50]:
        print(f"  {h}")
    return 0


def build_arg_parser(sub):
    p = sub.add_parser("osint", help="passive subdomain/scope expansion")
    p.add_argument("domain")
    p.add_argument("--in-scope", action="append", default=[])
    p.add_argument("--max-hosts", type=int, default=300)
    p.set_defaults(fn=cli_osint)
    return p
