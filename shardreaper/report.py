#!/usr/bin/env python3
"""
report.py — operator-facing report generation.

Renders REPORT.md from engagement state: mission, scope, targets, findings
with severity + ATT&CK mapping + evidence, executed actions, weapon/KB
references, and recommended next moves. Brutaal, terse, concrete.
"""
import os
from collections import Counter

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _attck_link(technique):
    tid = ""
    for part in str(technique or "").split():
        if part.startswith("T") and part[1:5].isdigit():
            tid = part[:9]
            break
    if not tid:
        return str(technique or "")
    return f"[{tid}](https://attack.mitre.org/techniques/{tid}/)"


def render_report(eng, kb=None):
    st = eng.state
    L = []
    a = L.append
    def nl():
        L.append("")
    a(f"# ShardReaper Engagement Report — {st.get('name', 'engagement')}")
    nl()
    a(f"- **Created:** {st.get('created')}  **Updated:** {st.get('updated')}")
    a(f"- **Phase:** {eng.phase}")
    a(f"- **Objective:** {st.get('objective') or '(not set)'}")
    a(f"- **Scope file:** {st.get('scope_path')}")
    nl()
    a("## 1. Mission Summary")
    nl()
    findings = st.get("findings", [])
    actions = st.get("actions", [])
    targets = st.get("targets", [])
    a(f"{len(targets)} target(s) engaged, {len(findings)} finding(s), "
      f"{len(actions)} logged action(s).")
    sev = Counter(f.get("severity", "info") for f in findings)
    a("Severity: " + ", ".join(f"{k.upper()} {v}" for k, v in sorted(
        sev.items(), key=lambda x: SEVERITY_ORDER.get(x[0], 9))))
    nl()
    a("## 2. Findings")
    nl()
    if not findings:
        a("_No confirmed findings yet — attack phase pending or target hardened._")
    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity", "info"), 9)):
        a(f"### {f['id']} — {f['title']}  `{f['severity'].upper()}`")
        nl()
        a(f"- **Target:** `{f['target']}`")
        a(f"- **Class:** {f.get('class') or f.get('type')}")
        a(f"- **ATT&CK:** {_attck_link(f.get('technique'))}")
        a(f"- **Detail:** {f.get('detail', '')}")
        if f.get("evidence"):
            a(f"- **Evidence:** `{f.get('evidence')}`")
        nl()
    a("## 3. Targets & Intel")
    nl()
    for t in targets:
        a(f"### {t['host']}")
        ports = t.get("ports") or {}
        if ports:
            a(f"- **Ports:** {', '.join(str(p) for p in sorted(ports))}")
        for u in t.get("urls", []):
            a(f"- **URL:** {u.get('url')} [{u.get('status')}] title={u.get('title', '')[:60]} "
              f"tech={','.join(u.get('tech') or [])}")
        hints = (t.get("intel") or {}).get("hints")
        if hints:
            a(f"- **Hints:** {', '.join(hints[:10])}")
        for f_ in t.get("findings", []):
            a(f"- **{f_.get('severity', 'info').upper()}** {f_.get('detail', '')[:160]}")
    nl()
    a("## 4. Attack Plan")
    nl()
    plan = st.get("plan", [])
    if not plan:
        a("_No plan items._")
    for p in plan[:25]:
        a(f"- `{p.get('severity', 'info').upper():5s}` {p.get('action')} — "
          f"{p.get('detail', '')[:110]}  [{_attck_link(p.get('technique'))}]")
    nl()
    a("## 5. Executed Actions (ledger)")
    nl()
    if not actions:
        a("_None._")
    for act in actions[-30:]:
        a(f"- `{act.get('ts', '')}` **{act.get('technique')}** {act.get('outcome')} @ "
          f"{act.get('target')} — {act.get('detail', '')[:100]}")
    nl()
    a("## 6. Knowledge & Weapons Referenced")
    nl()
    refs = set()
    for note in st.get("notes", []):
        for k in (note.get("kb") or []):
            refs.add(k)
    for r in sorted(refs)[:15]:
        a(f"- {r}")
    nl()
    a("## 7. Recommended Next Moves")
    nl()
    for f in [x for x in findings if x.get("severity") in ("high", "critical")][:6]:
        a(f"- Exploit **{f['title']}** at `{f['target']}` — chain into persistence/lateral.")
    high_ports = []
    for t in targets:
        for p in (t.get("ports") or {}):
            if p not in (22, 80, 443, 53):
                high_ports.append(f"{t['host']}:{p}")
    if high_ports:
        a(f"- Enumerate unusual services: `{', '.join(sorted(set(high_ports))[:10])}`")
    a("- Run tactical phases: `shardreaper run --phases escalate,persist,move,harvest,evade,exfil`")
    a("- Re-verify findings with fresh evidence before the debrief.")
    return "\n".join(L) + "\n"


# ---------------- platform reports (HackerOne / Bugcrowd / Intigriti) ----------------
VRT_MAP = {
    "rce": "server_security_misconfiguration",
    "sqli": "server_security_misconfiguration",
    "ssrf": "server_side_request_forgery_ssrf",
    "idor": "broken_access_control",
    "auth-bypass": "broken_authentication_and_session_management",
    "xss": "cross_site_scripting_xss",
    "cors": "cross_origin_resource_sharing_cors",
    "open-redirect": "unvalidated_redirects_and_forwards",
    "info-leak": "sensitive_data_exposure",
    "exposed-path": "sensitive_data_exposure",
    "weak-credentials": "weak_login_function",
    "missing-headers": "missing_or_misconfigured_security_headers",
    "tls": "improper_transport_layer_security",
    "dns-axfr": "information_disclosure",
}


def render_h1(eng, only_passed=True):
    """HackerOne markdown submission per finding."""
    parts = []
    for f in eng.state.get("findings", []):
        gate = f.get("gate")
        if only_passed and gate and not gate.get("passed"):
            continue
        parts.append(f"## {f['title']}\n")
        parts.append("**Weakness:** " + (f.get("class") or ""))
        parts.append("**Severity:** " + f.get("severity", "").upper())
        parts.append("**Target:** " + f.get("target", ""))
        parts.append("")
        parts.append("### Summary\n")
        parts.append(f.get("detail", "") + "\n")
        parts.append("### Steps to Reproduce\n")
        for i, ev in enumerate(f.get("evidence") or [str(f.get("evidence"))], 1):
            parts.append(f"{i}. {ev}")
        parts.append("\n### Impact\n")
        parts.append(f.get("impact") or "See Summary — concrete attacker-attainable harm described above.")
        parts.append("")
    if not parts:
        parts.append("_No passing findings to submit._")
    return "\n".join(parts) + "\n"


def render_bugcrowd(eng, only_passed=True):
    """Bugcrowd submission — VRT-mapped."""
    parts = []
    for f in eng.state.get("findings", []):
        gate = f.get("gate")
        if only_passed and gate and not gate.get("passed"):
            continue
        vrt = VRT_MAP.get((f.get("class") or "").lower(), "server_security_misconfiguration")
        parts.append(f"## {f['title']}\n")
        parts.append(f"- **VRT:** {vrt}")
        parts.append(f"- **Severity:** {f.get('severity', '').upper()}")
        parts.append(f"- **Target:** {f.get('target')}")
        parts.append(f"- **Description:** {f.get('detail', '')}")
        parts.append(f"- **Steps to Reproduce:** " + " ; ".join(f.get("evidence") or []))
        parts.append(f"- **Impact:** {f.get('impact') or 'Demonstrated attacker impact.'}")
        parts.append("")
    if not parts:
        parts.append("_No passing findings to submit._")
    return "\n".join(parts) + "\n"


def render_intigriti(eng, only_passed=True):
    """Intigriti submission — impact-first."""
    parts = []
    for f in eng.state.get("findings", []):
        gate = f.get("gate")
        if only_passed and gate and not gate.get("passed"):
            continue
        parts.append(f"## {f['title']}\n")
        parts.append("**Vulnerability class:** " + (f.get("class") or ""))
        parts.append("**Severity:** " + f.get("severity", "").upper())
        parts.append("**Endpoint:** " + f.get("target", ""))
        parts.append("")
        parts.append("**Description:** " + f.get("detail", ""))
        parts.append("**Reproduction:** " + " ".join(f.get("evidence") or []))
        parts.append("**Business impact:** " + (f.get("impact") or "Attacker-attainable harm as described."))
        parts.append("")
    if not parts:
        parts.append("_No passing findings to submit._")
    return "\n".join(parts) + "\n"


PLATFORM_RENDERERS = {"h1": render_h1, "bugcrowd": render_bugcrowd,
                      "intigriti": render_intigriti}


def cli_report(args):
    from .state import Engagement
    base = os.path.abspath(args.dir)
    if not os.path.isfile(os.path.join(base, "state.json")):
        print(f"no engagement at {base}")
        return 1
    eng = Engagement.load(base)
    if args.platform in PLATFORM_RENDERERS:
        md = PLATFORM_RENDERERS[args.platform](eng)
        out = os.path.join(base, f"REPORT-{args.platform.upper()}.md")
        with open(out, "w", encoding="utf-8") as f:
            f.write(md)
        print(f"{args.platform} report written: {out}")
        return 0
    md = render_report(eng)
    out = os.path.join(base, "REPORT.md")
    with open(out, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"report written: {out}")
    return 0


def build_arg_parser(sub):
    p = sub.add_parser("report", help="render REPORT.md from engagement state")
    p.add_argument("dir")
    p.add_argument("--platform", default="client",
                   choices=["client", "h1", "bugcrowd", "intigriti"],
                   help="report flavor (client default)")
    p.set_defaults(fn=cli_report)
    return p
