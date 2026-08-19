#!/usr/bin/env python3
"""
report.py — operator-facing report generation.

Renders REPORT.md from engagement state: mission, scope, targets, findings
with severity + ATT&CK mapping + evidence, executed actions, weapon/KB
references, and recommended next moves. Brutaal, terse, concrete.
"""
import os
import re
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
    a(f"# ShardReaper Engagement Report — {st.get('name', 'engagement')}")
    a("")
    a(f"- **Created:** {st.get('created')}  **Updated:** {st.get('updated')}")
    a(f"- **Phase:** {eng.phase}")
    a(f"- **Objective:** {st.get('objective') or '(not set)'}")
    a(f"- **Scope file:** {st.get('scope_path')}")
    a("")
    a("## 1. Mission Summary")
    a("")
    findings = st.get("findings", [])
    actions = st.get("actions", [])
    targets = st.get("targets", [])
    a(f"{len(targets)} target(s) engaged, {len(findings)} finding(s), "
      f"{len(actions)} logged action(s).")
    sev = Counter(f.get("severity", "info") for f in findings)
    a("Severity: " + ", ".join(f"{k.upper()} {v}" for k, v in sorted(
        sev.items(), key=lambda x: SEVERITY_ORDER.get(x[0], 9))))
    a("")
    a("## 2. Findings")
    a("")
    if not findings:
        a("_No confirmed findings yet — attack phase pending or target hardened._")
    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity", "info"), 9)):
        a(f"### {f['id']} — {f['title']}  `{f['severity'].upper()}`")
        a("")
        a(f"- **Target:** `{f['target']}`")
        a(f"- **Class:** {f.get('class') or f.get('type')}")
        a(f"- **ATT&CK:** {_attck_link(f.get('technique'))}")
        a(f"- **Detail:** {f.get('detail', '')}")
        if f.get("evidence"):
            a(f"- **Evidence:** `{f.get('evidence')}`")
        a("")
    a("## 3. Targets & Intel")
    a("")
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
    a("")
    a("## 4. Attack Plan")
    a("")
    plan = st.get("plan", [])
    if not plan:
        a("_No plan items._")
    for p in plan[:25]:
        a(f"- `{p.get('severity', 'info').upper():5s}` {p.get('action')} — "
          f"{p.get('detail', '')[:110]}  [{_attck_link(p.get('technique'))}]")
    a("")
    a("## 5. Executed Actions (ledger)")
    a("")
    if not actions:
        a("_None._")
    for act in actions[-30:]:
        a(f"- `{act.get('ts', '')}` **{act.get('technique')}** {act.get('outcome')} @ "
          f"{act.get('target')} — {act.get('detail', '')[:100]}")
    a("")
    a("## 6. Knowledge & Weapons Referenced")
    a("")
    refs = set()
    for note in st.get("notes", []):
        for k in (note.get("kb") or []):
            refs.add(k)
    for r in sorted(refs)[:15]:
        a(f"- {r}")
    a("")
    a("## 7. Recommended Next Moves")
    a("")
    for f in [x for x in findings if x.get("severity") in ("high", "critical")][:6]:
        a(f"- Exploit **{f['title']}** at `{f['target']}` — chain into persistence/lateral.")
    high_ports = []
    for t in targets:
        for p in (t.get("ports") or {}):
            if p not in (22, 80, 443, 53):
                high_ports.append(f"{t['host']}:{p}")
    if high_ports:
        a(f"- Enumerate unusual services: `{', '.join(sorted(set(high_ports))[:10])}`")
    a("- Run tactical phases: `shardreaper run --phases escalate,persist,move,harvest,spray,evade,exfil`")
    a("- Re-verify findings with fresh evidence before the debrief.")
    return "\n".join(L) + "\n"


# ---------------- report integrity: merge, never clobber ----------------
EMPTY_SECTION_LINES = (
    "_No confirmed findings yet — attack phase pending or target hardened._",
    "_No plan items._", "_None._",
    "_No passing findings to submit._",
)


def _sections(md):
    """Split a report into {heading: body} on top-level '## ' lines."""
    secs, cur, body = {}, None, []
    for line in (md or "").splitlines():
        if line.startswith("## "):
            if cur is not None:
                secs[cur] = "\n".join(body).strip("\n")
            cur, body = line[3:].strip(), []
        elif cur is not None:
            body.append(line)
    if cur is not None:
        secs[cur] = "\n".join(body).strip("\n")
    return secs


def is_empty_template_section(body):
    """A section that carries only italic placeholders — the empty template.
    Overwriting a real narrative with THIS is the sin the merge refuses."""
    lines = [l.strip() for l in (body or "").splitlines()
             if l.strip() and not l.startswith("- **Created")]
    if not lines:
        return True
    return all(l in EMPTY_SECTION_LINES or
               (l.startswith("_") and l.endswith("_")) for l in lines)


def narrative_present(md):
    """Does this report carry actual findings/actions content?"""
    secs = _sections(md)
    for h in ("2. Findings", "5. Executed Actions (ledger)"):
        body = secs.get(h, "")
        if body and not is_empty_template_section(body):
            return True
    return False


def merge_report(old, new):
    """Merge a fresh render into an existing report. Rules:

    * sections that exist in BOTH keep the fresh content — UNLESS the fresh
      section is the empty template, in which case the old narrative wins
      (refuse to overwrite a narrative with the empty template);
    * old-only sections are preserved (no narrative loss, ever);
    * new-only sections are appended.
    """
    old_secs, new_secs = _sections(old), _sections(new)
    header = (new or "").split("## ", 1)[0].rstrip()
    merged, order = {}, list(new_secs)
    for h, body in new_secs.items():
        ob = old_secs.get(h)
        if ob is not None and is_empty_template_section(body) \
                and not is_empty_template_section(ob):
            merged[h] = ob      # keep the narrative
        else:
            merged[h] = body
    for h, body in old_secs.items():
        if h not in merged:
            merged[h] = body
            order.append(h)
    out = [header + "\n\n",
           "> _merged with existing REPORT.md — narrative sections are "
           "preserved, never overwritten by empty templates_\n"]
    for h in order:
        out.append(f"## {h}\n{merged[h].strip()}\n")
    return "\n".join(out) + "\n"


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

# evidence hygiene — strip operator PII / session secrets before anything ships
REDACT_PATTERNS = [
    (r"[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}", "[JWT]"),
    (r"session(?:id)?\s*=\s*[A-Za-z0-9_\-]+", "session=[REDACTED]"),
    (r"cookie\s*[:=]\s*[^;\s]+", "cookie=[REDACTED]"),
    (r"(AKIA|ASIA)[A-Z0-9]{16}", "[AWS-KEY]"),
    (r"sk-[A-Za-z0-9]{20,}", "[API-KEY]"),
    (r"gh[pousr]_[A-Za-z0-9]{20,}", "[GH-TOKEN]"),
    (r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "[EMAIL]"),
    (r"password\s*[=:]\s*\S+", "password=[REDACTED]"),
    (r"Bearer\s+[A-Za-z0-9\-._]+", "Bearer [REDACTED]"),
]


def redact(md):
    for rx, repl in REDACT_PATTERNS:
        md = re.sub(rx, repl, md, flags=re.I)
    return md


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
    else:
        md = render_report(eng)
        out = os.path.join(base, "REPORT.md")
    if args.redact:
        md = redact(md)
    if args.force:
        with open(out, "w", encoding="utf-8") as f:
            f.write(md)
        print(f"report written: {out}{' (redacted)' if args.redact else ''}")
        return 0
    # integrity: merge with any existing report, refuse to clobber narrative
    if os.path.isfile(out):
        try:
            old = open(out, encoding="utf-8").read()
        except OSError:
            old = ""
        if old.strip():
            if narrative_present(old) and not narrative_present(md):
                print("refusing to overwrite narrative with the empty "
                      "template — merging instead")
            md = merge_report(old, md)
            print(f"report merged with existing {out} (narrative preserved)")
    with open(out, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"report written: {out}{' (redacted)' if args.redact else ''}")
    return 0


def build_arg_parser(sub):
    p = sub.add_parser("report", help="render REPORT.md from engagement state")
    p.add_argument("dir")
    p.add_argument("--platform", default="client",
                   choices=["client", "h1", "bugcrowd", "intigriti"],
                   help="report flavor (client default)")
    p.add_argument("--redact", action="store_true",
                   help="strip PII/session secrets from the output (evidence hygiene)")
    p.add_argument("--force", action="store_true",
                   help="overwrite without merging (explicit operator override)")
    p.set_defaults(fn=cli_report)
    return p
