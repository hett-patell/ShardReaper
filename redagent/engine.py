#!/usr/bin/env python3
"""
engine.py — the phase orchestrator.

Deterministic control flow; the LLM brain (if configured) only advises.
Scope is enforced in code at every boundary. State persists after every step:
a run is resumable and auditable.

    engage -> recon -> analyze -> plan -> attack
           -> escalate/persist/move/harvest/evade/exfil -> report

Usage:
    redagent engage demo --seeds http://10.0.0.5 --in-scope 10.0.0.0/24
    redagent run --phases recon,analyze,plan
    redagent run --phases attack --go           # execute (not just dry-run)
    redagent run --phases report
"""
import argparse
import json
import os
import sys

from .scope import Scope
from .state import Engagement, PHASES
from .knowledge import Knowledge
from .weapons import Weapons
from .atomics import AtomicIndex
from .recon import run_recon
from .persona import build_operator_prompt
from . import llm as LLM
from .report import render_report

# heuristic: service/port -> technique hints for plan ranking
PORT_TECH = {
    21: ["ftp", "anonymous"], 22: ["ssh", "brute"], 23: ["telnet"],
    25: ["smtp", "user-enum"], 53: ["dns", "zone-transfer"],
    80: ["web", "dir-bruteforce"], 443: ["web", "tls"],
    445: ["smb", "enum", "eternalblue"], 139: ["smb", "netbios"],
    1433: ["mssql"], 1521: ["oracle"], 3306: ["mysql"],
    3389: ["rdp", "bluekeep"], 5432: ["postgres"], 5900: ["vnc"],
    5985: ["winrm"], 5986: ["winrm"], 6379: ["redis", "unauth"],
    8080: ["web", "proxy"], 8443: ["web", "tls"], 8888: ["web"],
    9000: ["web", "panel"], 9200: ["elasticsearch", "unauth"],
    11211: ["memcached"], 27017: ["mongodb", "unauth"],
    2375: ["docker", "unauth"], 2049: ["nfs", "no-root-squash"],
}

EXPOSED_HIGH = ["/.git/HEAD", "/.git/config", "/.env", "/backup.zip",
                "/backup.sql", "/db.sql", "/config.php.bak", "/phpinfo.php",
                "/.svn/entries", "/.htaccess"]

PHASE_TECH_KEYWORDS = {
    "escalate": ["privilege escalation", "sudo", "setuid", "token", "service"],
    "persist": ["persistence", "scheduled task", "registry", "cron", "autorun"],
    "move": ["lateral movement", "psexec", "winrm", "pass the hash", "ssh"],
    "harvest": ["credential access", "mimikatz", "kerberoast", "hash", "password"],
    "evade": ["defense evasion", "amsi", "bypass", "obfuscation", "loader"],
    "exfil": ["exfiltration", "dns exfil", "sftp", "stealth"],
}


class Engine:
    def __init__(self, base, phases=None, go=False, mock=False, model=None,
                 parallel=8):
        self.base = base
        self.mock = mock
        self.go = go
        self.parallel = parallel
        self.eng = Engagement.load(base)
        self.scope = Scope.load(self.eng.scope_path)
        self.eng.log(f"engine start | scope={self.scope.name} phases={phases or 'default'} "
                     f"go={'EXECUTE' if go else 'DRY-RUN'} mock={mock}")
        self.kb = Knowledge()
        self.weapons = Weapons(self.kb.roots)
        atomic_root = self.kb.roots.get("atomic")
        self.atomics = AtomicIndex(atomic_root) if atomic_root else None
        self._phase_order = phases or ["recon", "analyze", "plan", "report"]

    # ---------------- knowledge helpers ----------------
    def kb_hits(self, query, limit=6):
        hits = self.kb.search(query, limit=limit)
        return [f"[{h['corpus']}] {h['title']} — {h['rel']}" for h in hits]

    def kb_lines(self, query, limit=4):
        return "\n".join(self.kb_hits(query, limit))

    # ---------------- phases ----------------
    def phase_recon(self):
        self.eng.set_phase("recon")
        if self.mock:
            self.eng.state["targets"] = [
                {"host": "localhost", "addrs": ["127.0.0.1"], "ports": {80: None},
                 "urls": [{"url": s, "status": 200, "title": "mock", "tech": []}],
                 "intel": {}, "findings": []} for s in self.scope.seeds]
            self.eng.save()
            self.eng.log(f"recon(mock): {len(self.eng.state['targets'])} target(s)")
            return
        targets = run_recon(self.scope, self.scope.seeds,
                            wordlist=os.path.join(os.path.dirname(self.base), "..", "data",
                                                  "wordlists", "subdomains.txt")
                            if False else None,
                            top_ports=100, log=self.eng.log)
        self.eng.state["targets"] = targets
        self.eng.save()
        self.eng.log(f"recon: {len(targets)} target(s) — "
                     f"{sum(1 for t in targets if t.get('findings'))} with intel hits")

    def phase_analyze(self):
        self.eng.set_phase("analyze")
        for t in self.eng.state["targets"]:
            host = t["host"]
            ports = t.get("ports") or {}
            hints = []
            for p in ports:
                for h in PORT_TECH.get(p, []):
                    if h not in hints:
                        hints.append(h)
            t["intel"]["hints"] = hints
            t["intel"]["kb"] = []
            if hints:
                t["intel"]["kb"] = self.kb_hits(" ".join(hints[:4]), limit=5)
            for f_ in t.get("findings", []):
                t["intel"]["kb"] += self.kb_hits(f_.get("detail", "")[:80], limit=2)
            t["intel"]["kb"] = list(dict.fromkeys(t["intel"]["kb"]))[:8]
            self.eng.log(f"analyze {host}: hints={hints[:8]}", "action")
        self.eng.save()

    def phase_plan(self):
        self.eng.set_phase("plan")
        plan = []
        for t in self.eng.state["targets"]:
            host = t["host"]
            for f_ in t.get("findings", []):
                sev = f_.get("severity", "low")
                if f_.get("type") == "exposed-path":
                    plan.append({"target": host, "action": "confirm-and-exploit",
                                 "detail": f_.get("path"), "severity": sev,
                                 "technique": "T1083 File and Directory Discovery",
                                 "atomic": self._pick_atomic(["file", "directory", "discovery"])})
                elif f_.get("type") == "dns-axfr":
                    plan.append({"target": host, "action": "dump-zone",
                                 "detail": "AXFR zone transfer", "severity": sev,
                                 "technique": "T1596.002 DNS",
                                 "atomic": None})
                elif f_.get("type") == "tls":
                    plan.append({"target": host, "action": "collect-cert",
                                 "detail": "expired TLS cert", "severity": sev,
                                 "technique": "T1595 Active Scanning",
                                 "atomic": None})
            for p in t.get("ports") or {}:
                hints = PORT_TECH.get(p, ["service"])
                plan.append({"target": host, "action": f"enumerate-port-{p}",
                             "detail": f"open port {p} — {' '.join(hints)}",
                             "severity": "info",
                             "technique": "T1046 Network Service Discovery",
                             "atomic": self._pick_atomic(hints[:3])})
            for u in t.get("urls", []):
                if u.get("status") == 200:
                    plan.append({"target": host, "action": "deep-web-audit",
                                 "detail": f"web audit {u.get('url')} tech={u.get('tech')}",
                                 "severity": "info",
                                 "technique": "T1595.003 Wordlist Scanning",
                                 "atomic": self._pick_atomic(["web", "directory", "scan"])})
        # LLM refinement when the brain is available
        if LLM.available() and not self.mock:
            self._llm_refine_plan(plan)
        self.eng.state["plan"] = plan
        self.eng.save()
        self.eng.log(f"plan: {len(plan)} items — {self._plan_severity_counts(plan)}")

    def _pick_atomic(self, keywords):
        if not self.atomics:
            return None
        sel = self.atomics.select(keywords, platform=self._host_platform(), limit=3)
        return [{"technique": s["technique"], "name": s["name"]} for s in sel]

    @staticmethod
    def _host_platform():
        return "linux" if os.name == "posix" else "windows"

    def _plan_severity_counts(self, plan):
        from collections import Counter
        return dict(Counter(p.get("severity", "info") for p in plan))

    def _llm_refine_plan(self, plan):
        self.eng.log("brain online — refining attack plan", "action")
        context = {
            "targets": [{k: t.get(k) for k in ("host", "ports", "urls", "findings", "intel")}
                        for t in self.eng.state["targets"]][:6],
            "plan_items": plan[:12],
        }
        sys = build_operator_prompt(self.scope.describe(),
                                    self.eng.state.get("objective", ""),
                                    llm_tools=True)
        text, js = LLM.decide(
            "Given the recon results, rank the top attack paths and chains. "
            "Return JSON: {\"priority\": [{\"target\": ..., \"action\": ..., "
            "\"technique\": ..., \"why\": ...}]} (max 8).",
            system=sys, context=context, want_json=True)
        if js and isinstance(js, dict) and isinstance(js.get("priority"), list):
            self.eng.log(f"brain ranked {len(js['priority'])} priority chains", "action")
            self.eng.state["notes"].append({"ts": self.eng.state["updated"],
                                            "kind": "llm-plan", "data": js["priority"]})
            self.eng.save()

    def phase_attack(self):
        self.eng.set_phase("attack")
        plan = self.eng.state.get("plan", [])
        items = [p for p in plan if p.get("severity") != "info"]
        if not items:
            items = plan
            self.eng.log("no high-severity items — attacking info-level plan (recon coverage)", "warn")
        for item in items:
            target = item["target"]
            if not self.scope.in_scope_host(target):
                self.eng.log(f"skip {target}: out of scope", "warn")
                continue
            self.eng.log(f"attack {target} — {item['action']} ({item['detail'][:80]})",
                         "action")
            if item.get("atomic"):
                for at in item["atomic"]:
                    tech = self.atomics.get(at["technique"])
                    if not tech:
                        continue
                    test = next((t for t in tech["tests"] if t.get("name") == at["name"]), None)
                    if not test:
                        continue
                    r = self.atomics.run_test(test, atomics_path=os.path.join(
                        self.atomics.root, "atomics"), dry_run=not self.go, timeout=90)
                    self.eng.log_action(
                        technique=at["technique"], target=target,
                        detail=at["name"], outcome="executed" if not r.get("dry_run") else "dry-run",
                        evidence=[r.get("cmd", "")[:300]], result=r.get("stdout", "")[:300]
                        if r.get("stdout") else r.get("error"))
                    if r.get("dry_run"):
                        self.eng.log(f"  [{at['technique']}] {at['name']} (dry-run — pass --go)",
                                     "action")
                    else:
                        self.eng.log(f"  [{at['technique']}] rc={r.get('returncode')} "
                                     f"{r.get('stdout', r.get('error', ''))[:100]}", "action")
            else:
                self.eng.log_action(technique=item.get("technique", "?"),
                                    target=target, detail=item["detail"],
                                    outcome="planned")
        self.eng.save()

    def phase_tactical(self, key, phase):
        """escalate/persist/move/harvest/evade/exfil — knowledge + weapon selection."""
        self.eng.set_phase(phase)
        kw = PHASE_TECH_KEYWORDS[key]
        self.eng.log(f"{phase}: selecting techniques from corpus…", "action")
        kb = self.kb_lines(" ".join(kw[:3]), limit=6)
        for line in kb:
            self.eng.log(f"  KB  {line}", "action")
        if self.atomics:
            sel = self.atomics.select(kw, platform=self._host_platform(), limit=6)
            for s in sel:
                self.eng.log(f"  AT  [{s['technique']}] {s['name']}", "action")
        weapons = self.weapons.by_phase(phase, limit=8)
        for w in weapons[:6]:
            self.eng.log(f"  WPN {w['name']} — {w['url']}", "action")
        self.eng.state["notes"].append({"ts": self.eng.state["updated"],
                                        "kind": f"tactical-{phase}",
                                        "kb": kb, "weapons": [w["name"] for w in weapons[:8]]})
        self.eng.save()

    def phase_report(self):
        self.eng.set_phase("report")
        md = render_report(self.eng, self.kb)
        out = os.path.join(self.base, "REPORT.md")
        with open(out, "w", encoding="utf-8") as f:
            f.write(md)
        self.eng.log(f"report written: {out} ({len(md)} bytes)")
        return out

    # ---------------- driver ----------------
    def run(self):
        for phase in self._phase_order:
            if phase == "recon":
                self.phase_recon()
            elif phase == "analyze":
                self.phase_analyze()
            elif phase == "plan":
                self.phase_plan()
            elif phase == "attack":
                self.phase_attack()
            elif phase == "report":
                self.phase_report()
            elif phase in PHASE_TECH_KEYWORDS:
                self.phase_tactical(phase, phase)
            else:
                self.eng.log(f"unknown phase {phase}", "err")
        self.eng.log("engine complete")


def engage(base, name, seeds, in_scope, out_of_scope, objective="", mock=False):
    os.makedirs(base, exist_ok=True)
    scope_path = os.path.join(base, "scope.json")
    with open(scope_path, "w", encoding="utf-8") as f:
        json.dump({"name": name, "in_scope": in_scope or [],
                   "out_of_scope": out_of_scope or [], "seeds": seeds or []}, f, indent=2)
    eng = Engagement(base, name, scope_path)
    eng.state["seeds"] = seeds or []
    if objective:
        eng.state["objective"] = objective
    eng.save()
    eng.log(f"engagement created: {base} (scope: {len(in_scope or [])} in / "
            f"{len(out_of_scope or [])} out / {len(seeds or [])} seeds)")
    print()
    print(Scope.load(scope_path).describe())
    return base


def cli_engage(args):
    engage(args.dir, args.name, args.seeds or [], args.in_scope or [],
           args.out_of_scope or [], args.objective, args.mock)


def cli_run(args):
    base = os.path.abspath(args.dir)
    if not os.path.isfile(os.path.join(base, "state.json")):
        print(f"no engagement at {base} — run: redagent engage ...")
        return 1
    phases = [p.strip() for p in args.phases.split(",") if p.strip()] if args.phases \
        else ["recon", "analyze", "plan", "report"]
    eng = Engine(base, phases=phases, go=args.go, mock=args.mock)
    eng.run()
    return 0


def cli_status(args):
    base = os.path.abspath(args.dir)
    if not os.path.isfile(os.path.join(base, "state.json")):
        print(f"no engagement at {base}")
        return 1
    eng = Engagement.load(base)
    print(f"engagement: {eng.state['name']}  phase: {eng.phase}")
    print(f"  created: {eng.state['created']}  updated: {eng.state['updated']}")
    print(f"  scope:   {eng.scope_path}")
    print(f"  seeds:   {eng.state.get('seeds')}")
    print(f"  targets: {len(eng.state.get('targets', []))}")
    print(f"  findings:{len(eng.state.get('findings', []))}")
    for f_ in eng.state.get("findings", []):
        print(f"    {f_['id']} {f_['severity'].upper():7s} {f_['title']} @ {f_['target']}")
    print(f"  actions: {len(eng.state.get('actions', []))}")
    print(f"  plan:    {len(eng.state.get('plan', []))} items")
    print(f"  ledger:  {eng.ledger_path}")
    return 0


def build_arg_parser(sub):
    ep = sub.add_parser("engage", help="create an engagement (authorization + seeds)")
    ep.add_argument("dir", help="engagement folder")
    ep.add_argument("--name", default="engagement")
    ep.add_argument("--seeds", action="append", default=[], help="seed URLs/hosts (repeat)")
    ep.add_argument("--in-scope", action="append", default=[], help="in-scope pattern (repeat)")
    ep.add_argument("--out-of-scope", action="append", default=[], help="out-of-scope (repeat)")
    ep.add_argument("--objective", default="")
    ep.add_argument("--mock", action="store_true")
    ep.set_defaults(fn=cli_engage)

    rp = sub.add_parser("run", help="run engagement phases")
    rp.add_argument("dir", help="engagement folder")
    rp.add_argument("--phases", default="", help="comma list: recon,analyze,plan,attack,"
                    "escalate,persist,move,harvest,evade,exfil,report")
    rp.add_argument("--go", action="store_true", help="EXECUTE atomic tests (default dry-run)")
    rp.add_argument("--mock", action="store_true")
    rp.set_defaults(fn=cli_run)

    sp = sub.add_parser("status", help="engagement status")
    sp.add_argument("dir")
    sp.set_defaults(fn=cli_status)
    return sub
