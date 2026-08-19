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
    a(f"# RedAgent Engagement Report — {st.get('name', 'engagement')}")
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
    a("- Run tactical phases: `redagent run --phases escalate,persist,move,harvest,evade,exfil`")
    a("- Re-verify findings with fresh evidence before the debrief.")
    return "\n".join(L) + "\n"


def cli_report(args):
    from .state import Engagement
    base = os.path.abspath(args.dir)
    if not os.path.isfile(os.path.join(base, "state.json")):
        print(f"no engagement at {base}")
        return 1
    eng = Engagement.load(base)
    md = render_report(eng)
    out = os.path.join(base, "REPORT.md")
    with open(out, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"report written: {out}")
    return 0


def build_arg_parser(sub):
    p = sub.add_parser("report", help="render REPORT.md from engagement state")
    p.add_argument("dir")
    p.set_defaults(fn=cli_report)
    return p
