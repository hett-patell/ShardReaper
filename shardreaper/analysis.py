#!/usr/bin/env python3
"""
analysis.py — the operator's decision layer.

  triage   — the 7-Question Gate: submit or kill, before any report time.
  validate — full 4-gate check (scope, impact, evidence, severity).
  chain    — build A→B→C exploit chains from a confirmed finding.
  surface  — rank the discovered attack surface (P1 / P2 / kill list).
  intel    — map the target's tech stack to CVEs and attack playbooks.
  map      — route a class/technique to playbooks + atomics + weapons.

All deterministic; the LLM brain (if configured) only refines.
"""
import json
import os
import re

GATE_QUESTIONS = [
    ("q1", "Is the target in the operator's authorized scope?"),
    ("q2", "Does the finding demonstrate REAL impact (not a hygiene observation)?"),
    ("q3", "Is the impact type accepted (no N/A classes for the program)?"),
    ("q4", "Is there captured evidence (request/response, output, screenshots)?"),
    ("q5", "Are the steps reproducible in 5 steps or fewer?"),
    ("q6", "Is it a duplicate of an already-reported finding? (must be NO)"),
    ("q7", "Is the severity honest — not inflated, not under-sold?"),
]
GATE_NEGATIVE = {"q6"}

# classes a program will reject on sight — kill these before writing anything
ALWAYS_REJECTED = [
    "self-xss", "missing best-practice header alone", "version disclosure alone",
    "clickjacking without demonstrated impact", "spf/dmarc alone",
    "mixed content", "error page stack trace alone", "cookies without secure flag alone",
    "rate limiting on login (unless lockout/ATO)", "ssl cert expiry alone",
]


def _is_always_rejected(f):
    blob = f"{f.get('title', '')} {f.get('class', '')} {f.get('detail', '')}".lower()
    return any(k in blob for k in ALWAYS_REJECTED)


def run_gate(answers, note=""):
    """answers: dict qN -> bool (or string 'yes'/'no'). Returns gate result."""
    passed = True
    for qid, _q in GATE_QUESTIONS:
        a = answers.get(qid)
        if isinstance(a, str):
            a = a.strip().lower() in ("yes", "y", "true", "1")
        want = qid in GATE_NEGATIVE
        if bool(a) == want:
            passed = False
    decision = "submit" if passed else "kill"
    return {"passed": passed, "decision": decision, "answers": answers,
            "note": note}


def triage(eng, finding_ids=None, interactive=True, assume_yes=False):
    """Run the gate over findings (default: all not yet gated)."""
    out = []
    findings = [f for f in eng.state.get("findings", [])
                if finding_ids is None or f["id"] in finding_ids]
    for f in findings:
        if _is_always_rejected(f):
            f["gate"] = {"passed": False, "decision": "kill",
                         "answers": {}, "note": "always-rejected class"}
            eng.log(f"triage {f['id']}: KILL (always-rejected class)", "err")
            out.append((f, f["gate"]))
            continue
        if interactive and not assume_yes:
            print(f"\n=== triage {f['id']} — {f['title'][:70]} "
                  f"[{f.get('severity', '?')}] ===")
            answers = {}
            for qid, q in GATE_QUESTIONS:
                a = input(f"  {q} [y/n] ").strip().lower()
                answers[qid] = a in ("y", "yes", "")
            result = run_gate(answers)
        else:
            result = run_gate({qid: (qid not in GATE_NEGATIVE)
                               for qid, _q in GATE_QUESTIONS})
        f["gate"] = result
        tag = "PASS" if result["passed"] else "KILL"
        eng.log(f"triage {f['id']}: {tag} ({result['decision']})",
                "win" if result["passed"] else "err")
        out.append((f, result))
    eng.save()
    return out


def validate(eng, finding_ids=None, assume_yes=False):
    """Full validation: 7-Question Gate + always-rejected list + 4 pre-submission gates."""
    results = triage(eng, finding_ids, interactive=not assume_yes, assume_yes=assume_yes)
    for f, gate in results:
        if not gate.get("passed"):
            continue
        checks = {
            "demonstrable-now": bool(f.get("evidence")),
            "accepted-impact": not _is_always_rejected(f),
            "evidence-hygiene": True,   # enforced by report --redact
            "honest-severity": f.get("severity") in
                ("critical", "high", "medium", "low", "info"),
        }
        gate["checks"] = checks
        gate["passed"] = all(checks.values())
        if not gate["passed"]:
            gate["decision"] = "kill"
            eng.log(f"validate {f['id']}: KILL (failed: "
                    f"{[k for k, v in checks.items() if not v]})", "err")
        else:
            eng.log(f"validate {f['id']}: PASS — write the report", "win")
    eng.save()
    return results


# ---------------- chain builder ----------------
CHAIN_PATTERNS = {
    "idor": [("ato", "chain the object swap into account takeover — session, email, password reset"),
             ("mass-data", "scale the IDOR into full dataset extraction")],
    "exposed-git": [("source-review", "clone the repo — hardcoded secrets, keys, history"),
                    ("config-rce", "config/env leaks -> credential reuse -> RCE paths")],
    "exposed-path": [("secret-harvest", "the exposed file's contents -> credentials -> next door"),
                     ("source-review", "source/config review for hardcoded secrets")],
    "ssrf": [("cloud-metadata", "probe 169.254.169.254 / IMDS for IAM credentials"),
             ("internal-services", "pivot to internal admin panels and services")],
    "open-redirect": [("oauth-theft", "redirect carries the OAuth code/token off-site"),
                      ("phishing", "weaponize the redirect in social-engineering")],
    "xss": [("session-theft", "steal cookies/session -> account takeover"),
            ("phishing", "in-page credential harvest")],
    "sqli": [("db-dump", "extract tables, hashes, secrets"),
             ("rce", "INTO OUTFILE / xp_cmdshell / stacked queries")],
    "weak-credentials": [("reuse", "spray the password across every service"),
                         ("lateral", "the account's reach -> lateral movement")],
    "cors": [("data-theft", "read responses cross-origin in a victim's browser"),
             ("ato", "combine with auth endpoints")],
    "missing-headers": [("clickjacking", "frame the app for UI redressing"),
                        ("xss", "weak CSP makes injected scripts easier")],
    "tls": [("mitm", "expired/misconfigured TLS weakens transport"),
            ("credential-capture", "downgrade + capture")],
    "dns-axfr": [("internal-map", "zone data reveals the internal estate"),
                 ("subdomain-expansion", "every record is a new door")],
}

CHAIN_FALLBACK = [("deep-audit", "map the surrounding attack surface"),
                  ("evidence", "strengthen proof before escalating")]


def chain(eng, kb, finding_id=None, class_=None):
    """A→B→C: what to combine this finding with for maximum impact."""
    f = None
    if finding_id:
        f = next((x for x in eng.state.get("findings", []) if x["id"] == finding_id), None)
        class_ = class_ or (f or {}).get("class") or (f or {}).get("type")
    steps = CHAIN_PATTERNS.get(class_ or "", CHAIN_FALLBACK)
    lines = [f"chain for {class_ or finding_id}:"]
    for step_id, why in steps:
        hits = kb.search(f"{class_} {step_id}", limit=3)
        kb_line = hits[0]["rel"] if hits else "kb: no direct hit"
        lines.append(f"  {step_id}: {why}")
        lines.append(f"      -> {kb_line}")
    if f:
        lines.insert(1, f"  anchor: {f['id']} {f.get('title', '')[:70]} @ {f.get('target')}")
    return "\n".join(lines)


# ---------------- surface ranking ----------------
def surface(eng):
    """P1 (start here) / P2 (after) / kill list (skip) from engagement state."""
    p1, p2, kill = [], [], []
    for t in eng.state.get("targets", []):
        host = t["host"]
        for f_ in t.get("findings", []):
            sev = f_.get("severity", "low")
            item = f"{host}: {f_.get('detail', f_.get('type', ''))[:100]}"
            (p1 if sev in ("high", "critical") else p2).append((sev, item))
        for u in t.get("urls", []):
            if u.get("status") == 200:
                p2.append(("info", f"{u.get('url')} [{u.get('status')}] "
                                   f"tech={','.join(u.get('tech') or [])}"))
        for p in t.get("ports") or {}:
            if p not in (22, 53, 80, 443):
                p2.append(("info", f"{host}:{p} unusual service"))
    for f in eng.state.get("findings", []):
        g = f.get("gate")
        if g and not g.get("passed"):
            kill.append(f"{f['id']} {f.get('title', '')[:70]} (gate: KILL)")
    out = ["SURFACE RANKING", f"  P1 — start here ({len(p1)}):"]
    out += [f"    [{s.upper():7s}] {i}" for s, i in sorted(p1, reverse=True)[:10]]
    out += [f"  P2 — after P1 ({len(p2)}):"]
    out += [f"    [{s.upper():7s}] {i}" for s, i in p2[:12]]
    out += [f"  KILL LIST — skip ({len(kill)}):"]
    out += [f"    {i}" for i in kill[:8]]
    return "\n".join(out)


# ---------------- classify ----------------
CLASS_SIGNATURES = [
    (r"(graphql|/graphql)", "graphql"), (r"(oauth|authorize\?)", "oauth"),
    (r"(swagger|openapi|/api/)", "api-misconfig"), (r"(\.jwt|token=)", "jwt"),
    (r"(upload|/files/)", "file-upload"), (r"(\.json|rest)", "spa-api"),
    (r"(wp-|wordpress)", "wordpress"), (r"(asp|\.aspx)", "aspnet"),
    (r"(sharepoint|_layouts)", "sharepoint"), (r"(spring|actuator)", "springboot"),
    (r"(\.php)", "php"), (r"(login|signin|auth)", "auth-bypass"),
    (r"(\.git|\.env|backup)", "source-leak"), (r"(next\.js|__next)", "nextjs"),
    (r"(vcenter|vmware)", "vcenter"), (r"(m365|office365|login\.microsoft)", "m365"),
    (r"(okta|saml|sso)", "saml"), (r"(vpn|sslvpn)", "vpn-appliance"),
]


def classify(surface, kb, limit=6):
    """Map a URL/tech-string to the attack classes + playbooks that apply."""
    blob = surface.lower()
    classes = sorted({c for rx, c in CLASS_SIGNATURES if re.search(rx, blob)})
    lines = [f"classify: {surface}"]
    if not classes:
        lines.append("  no strong signature — run shardreaper recon for tech detection")
    for c in classes:
        lines.append(f"  [{c}]")
        hits = kb.search(f"{c} exploit", limit=3)
        for h in hits:
            lines.append(f"      {h['corpus']:12s} {h['title'][:60]} — {h['rel']}")
    return "\n".join(lines)


# ---------------- intel (offline corpus + optional NVD online) ----------------
def nvd_lookup(keyword, timeout=15, limit=8):
    """NVD CVE keyword search (services.nvd.nist.gov, keyless, best-effort)."""
    import urllib.request
    import urllib.parse
    q = urllib.parse.quote(keyword)
    url = ("https://services.nvd.nist.gov/rest/json/cves/2.0"
           f"?keywordSearch={q}&resultsPerPage={limit}")
    req = urllib.request.Request(url, headers={"User-Agent": "ShardReaper/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
        out = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cid = cve.get("id", "")
            desc = (cve.get("descriptions") or [{}])[0].get("value", "")[:140]
            sev = ""
            try:
                sev = cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
            except Exception:
                pass
            out.append((cid, sev, desc))
        return out
    except Exception:
        return None


# lesson 20 boundary: ONLY vendor/vuln sources. Box writeups are never
# queried — the advisory boundary is the software, not the target.
ADVISORY_HOSTS = ("services.nvd.nist.gov", "api.github.com", "api.opencve.io")


def ghsa_lookup(product, timeout=15, limit=8):
    """GitHub Security Advisories, keyless public API."""
    import urllib.request
    import urllib.parse
    q = urllib.parse.quote(f'"{product}"')
    url = ("https://api.github.com/advisories"
           f"?query={q}&per_page={limit}&type=reviewed")
    req = urllib.request.Request(url, headers={
        "User-Agent": "ShardReaper/1.3", "Accept":
        "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
        return [{"id": a.get("ghsa_id", ""), "severity":
                 (a.get("severity") or "").upper(),
                 "summary": (a.get("summary") or "")[:140],
                 "cve": a.get("cve_id") or ""} for a in data[:limit]]
    except Exception:
        return None


def searchsploit_lookup(product, timeout=30):
    """Local exploit-db search (searchsploit binary when present)."""
    import shutil
    import subprocess
    if not shutil.which("searchsploit"):
        return "missing"
    try:
        p = subprocess.run(["searchsploit", "--colour", "-t", product],
                           capture_output=True, text=True, timeout=timeout)
        lines = [ln.strip() for ln in p.stdout.splitlines()
                 if ln.strip() and not ln.startswith("-")]
        return lines[:12] if p.returncode == 0 else None
    except (subprocess.TimeoutExpired, OSError):
        return None


def advisory_lookup(product, version=None, limit=8, timeout=15,
                    offline=False):
    """Fingerprint -> advisory mapping. Sources: NVD (keyless), GHSA
    (keyless), local searchsploit. Returns a report dict; never raises,
    never leaves the ADVISORY_HOSTS boundary."""
    query = f"{product} {version}".strip() if version else product
    report = {"product": product, "version": version, "nvd": None,
              "ghsa": None, "searchsploit": "missing", "offline": False}
    if offline:
        report["offline"] = True
        return report
    report["nvd"] = nvd_lookup(query, timeout=timeout, limit=limit)
    report["ghsa"] = ghsa_lookup(product, timeout=timeout, limit=limit)
    report["searchsploit"] = searchsploit_lookup(product)
    if report["nvd"] is None and report["ghsa"] is None:
        report["offline"] = True
    return report


def _fingerprints(eng):
    """Product+version fingerprints harvested from recon state."""
    out = []
    for t in eng.state.get("targets", []):
        for u in t.get("urls", []):
            server = (u.get("server") or "").strip()
            if server:
                out.append(("server", server))
            for tech in (u.get("tech") or []):
                out.append(("tech", tech))
        nmap = (t.get("intel") or {}).get("nmap") or []
        for svc in nmap:
            prod = " ".join(p for p in (svc.get("product"),
                                        svc.get("version")) if p)
            if prod:
                out.append(("nmap", prod))
    return out


def advisory_map(eng, log=None, offline=False, limit=6):
    """The automatic analyze-phase step (lesson 20): every fingerprint is
    mapped to public advisories and stored as ordered attack candidates.
    Offline mode records the gap instead of hanging."""
    log = log or (lambda m: None)
    existing = {a.get("product") for a in eng.state.get("advisories", [])}
    for kind, product in _fingerprints(eng):
        key = product
        if key in existing:
            continue
        report = advisory_lookup(product, limit=limit, offline=offline)
        eng.state.setdefault("advisories", []).append(report)
        nvd = report["nvd"] or []
        ghsa = report["ghsa"] or []
        if nvd or ghsa:
            top = (nvd or ghsa)[0]
            cid = top[0] if isinstance(top, tuple) else top.get("id") or \
                top.get("cve") or "?"
            log(f"advisory: {product} -> {cid} "
                f"({len(nvd) + len(ghsa)} hit(s))", "action")
        elif report["offline"]:
            log(f"advisory: {product} -> offline (recorded gap)", "warn")
        else:
            log(f"advisory: {product} -> no public advisories", "info")
    eng.save()
    return eng.state.get("advisories", [])


def intel(eng, kb, query=None, online=False):
    """Tech-stack → CVE/playbook intel. Local corpus first; NVD optional."""
    techs = set()
    for t in eng.state.get("targets", []):
        for u in t.get("urls", []):
            techs.update(u.get("tech") or [])
        techs.update((t.get("intel") or {}).get("hints") or [])
    lines = [f"intel for {eng.state.get('name')} "
             f"(tech: {', '.join(sorted(techs)[:12]) or 'unknown'})"]
    for tech in sorted(techs)[:6]:
        hits = kb.search(f"{tech} cve exploit vulnerability", limit=3)
        if hits:
            lines.append(f"  [{tech}]")
            for h in hits:
                lines.append(f"      {h['corpus']:12s} {h['title'][:60]} — {h['rel']}")
        if online:
            cves = nvd_lookup(tech)
            if cves:
                lines.append(f"  [nvd: {tech}]")
                for cid, sev, desc in cves[:5]:
                    lines.append(f"      {cid} [{sev or '?'}] {desc}")
            else:
                lines.append(f"  [nvd: {tech}] unreachable (offline?)")
    if query:
        hits = kb.search(query, limit=6)
        lines.append(f"  [query: {query}]")
        for h in hits:
            lines.append(f"      {h['corpus']:12s} {h['title'][:60]} — {h['rel']}")
    return "\n".join(lines)


# ---------------- map: class -> playbooks + atomics + weapons ----------------
def map_class(kb, atomics, weapons, query, platform=None):
    lines = [f"map: {query}"]
    hits = kb.search(query, limit=6)
    lines.append("  playbooks:")
    for h in hits:
        lines.append(f"    [{h['corpus']:12s}] {h['title'][:60]} — {h['rel']}")
    if atomics:
        sel = atomics.select(query.split(), platform=platform, limit=6, strict=True)
        lines.append("  atomics:")
        for s in sel:
            lines.append(f"    [{s['technique']}] {s['name'][:70]}")
    ws = weapons.search(query, limit=6)
    lines.append("  weapons:")
    for w in ws:
        lines.append(f"    {w['name']:24s} {w['url']}")
    return "\n".join(lines)


# ---------------- CLI wiring helpers ----------------
def _load_engine(args_dir):
    from .state import Engagement
    from .scope import Scope
    from .knowledge import Knowledge
    from .weapons import Weapons
    from .atomics import AtomicIndex
    base = os.path.abspath(args_dir)
    if not os.path.isfile(os.path.join(base, "state.json")):
        print(f"no engagement at {base} — run: shardreaper engage ...")
        return None
    eng = Engagement.load(base)
    kb = Knowledge()
    atomic_root = kb.roots.get("atomic")
    atomics = AtomicIndex(atomic_root) if atomic_root else None
    weapons = Weapons(kb.roots)
    return eng, kb, atomics, weapons


def cli_triage(args):
    ctx = _load_engine(args.dir)
    if not ctx:
        return 1
    eng = ctx[0]
    triage(eng, args.finding_ids or None, interactive=not args.yes,
           assume_yes=args.yes)
    return 0


def cli_validate(args):
    ctx = _load_engine(args.dir)
    if not ctx:
        return 1
    eng = ctx[0]
    validate(eng, args.finding_ids or None, assume_yes=args.yes)
    return 0


def cli_intel(args):
    ctx = _load_engine(args.dir)
    if not ctx:
        return 1
    if args.product:
        report = advisory_lookup(args.product, version=args.version,
                                 limit=args.limit)
        print(f"advisory map: {args.product}"
              + (f" {args.version}" if args.version else ""))
        for src in ("nvd", "ghsa"):
            hits = report.get(src)
            if hits is None:
                print(f"  [{src}] unreachable (offline?)")
            else:
                for h in hits[:8]:
                    if isinstance(h, tuple):
                        print(f"  [{src}] {h[0]} [{h[1] or '?'}] {h[2]}")
                    else:
                        print(f"  [{src}] {h.get('id')} "
                              f"[{h.get('severity', '?')}] "
                              f"{h.get('summary', '')[:120]}")
        if report.get("searchsploit") == "missing":
            print("  [searchsploit] not installed")
        elif report.get("searchsploit"):
            for line in report["searchsploit"]:
                print(f"  [searchsploit] {line}")
        return 0
    print(intel(ctx[0], ctx[1], " ".join(args.query) if args.query else None,
                online=args.online))
    return 0


def cli_classify(args):
    from .knowledge import Knowledge
    print(classify(" ".join(args.target), Knowledge()))
    return 0


def cli_surface(args):
    ctx = _load_engine(args.dir)
    if not ctx:
        return 1
    print(surface(ctx[0]))
    return 0


def cli_chain(args):
    ctx = _load_engine(args.dir)
    if not ctx:
        return 1
    print(chain(ctx[0], ctx[1], args.finding, args.class_))
    return 0


def cli_map(args):
    from .knowledge import Knowledge
    from .weapons import Weapons
    from .atomics import AtomicIndex
    kb = Knowledge()
    roots = kb.roots
    atomics = AtomicIndex(roots["atomic"]) if "atomic" in roots else None
    weapons = Weapons(roots)
    print(map_class(kb, atomics, weapons, " ".join(args.query)))
    return 0


def build_arg_parser(sub):
    t = sub.add_parser("triage", help="7-Question Gate: submit or kill a finding")
    t.add_argument("dir", help="engagement folder")
    t.add_argument("finding_ids", nargs="*", help="optional finding ids (default: all ungated)")
    t.add_argument("--yes", action="store_true", help="non-interactive pass")
    t.set_defaults(fn=cli_triage)

    v = sub.add_parser("validate", help="full validation: gate + always-rejected + 4 checks")
    v.add_argument("dir", help="engagement folder")
    v.add_argument("finding_ids", nargs="*")
    v.add_argument("--yes", action="store_true")
    v.set_defaults(fn=cli_validate)

    i = sub.add_parser("intel", help="tech-stack -> CVE/playbook intel")
    i.add_argument("dir")
    i.add_argument("query", nargs="*")
    i.add_argument("--online", action="store_true", help="also query NVD (keyless)")
    i.add_argument("--product", default=None,
                   help="advisory map for a fingerprint: product name "
                        "(lesson 20: NVD/GHSA/searchsploit — vendor/vuln "
                        "sources only, never box writeups)")
    i.add_argument("--version", default=None, help="product version")
    i.add_argument("--limit", type=int, default=8)
    i.set_defaults(fn=cli_intel)

    cl = sub.add_parser("classify", help="map a URL/tech string to attack classes")
    cl.add_argument("target", nargs="+")
    cl.set_defaults(fn=cli_classify)

    s = sub.add_parser("surface", help="ranked attack surface (P1/P2/kill list)")
    s.add_argument("dir")
    s.set_defaults(fn=cli_surface)

    c = sub.add_parser("chain", help="build an A→B→C exploit chain")
    c.add_argument("dir")
    c.add_argument("--finding", default=None, help="finding id to anchor on")
    c.add_argument("--class", dest="class_", default=None, help="or a class name directly")
    c.set_defaults(fn=cli_chain)

    m = sub.add_parser("map", help="route a class to playbooks + atomics + weapons")
    m.add_argument("query", nargs="+")
    m.set_defaults(fn=cli_map)
    return sub
