#!/usr/bin/env python3
"""
engine.py — the phase orchestrator.

Deterministic control flow; the LLM brain (if configured) only advises.
Scope is enforced in code at every boundary. State persists after every step:
a run is resumable and auditable.

    engage -> recon -> analyze -> plan -> attack
           -> escalate/persist/move/harvest/evade/exfil -> report

Usage:
    shardreaper engage demo --seeds http://10.0.0.5 --in-scope 10.0.0.0/24
    shardreaper run --phases recon,analyze,plan
    shardreaper run --phases attack --go           # execute (not just dry-run)
    shardreaper run --phases report
"""
import json
import os

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
    80: ["web server", "wordlist scan"], 443: ["web server", "tls"],
    445: ["smb", "enum", "eternalblue"], 139: ["smb", "netbios"],
    1433: ["mssql"], 1521: ["oracle"], 3306: ["mysql"],
    3389: ["rdp", "bluekeep"], 5432: ["postgres"], 5900: ["vnc"],
    5985: ["winrm"], 5986: ["winrm"], 6379: ["redis", "unauth"],
    8080: ["web server", "proxy"], 8443: ["web server", "tls"], 8888: ["web server"],
    9000: ["web server", "panel"], 9200: ["elasticsearch", "unauth"],
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

# tactical phase -> weapons-catalog phase (catalogs use ATT&CK-ish names)
TACTICAL_WEAPON_PHASES = {
    "escalate": "privilege-escalation",
    "persist": "persistence",
    "move": "lateral-movement",
    "harvest": "credential-access",
    "evade": "defense-evasion",
    "exfil": ["exfiltration", "c2"],
}


class Engine:
    def __init__(self, base, phases=None, go=False, mock=False, model=None,
                 parallel=8, wordlist=None, top_ports=100, paths=True, osint=True):
        self.base = base
        self.mock = mock
        self.go = go
        self.parallel = parallel
        self.wordlist = wordlist
        self.top_ports = top_ports
        self.paths = paths
        self.osint = osint
        self.eng = Engagement.load(base)
        self.scope = Scope.load(self.eng.scope_path)
        self.eng.log(f"engine start | scope={self.scope.name} phases={phases or 'default'} "
                     f"go={'EXECUTE' if go else 'DRY-RUN'} mock={mock}")
        # cross-engagement memory: mark this session on every seed host
        try:
            from . import memory
            for seed in self.scope.seeds:
                h = seed.split("//")[-1].split("/")[0].split(":")[0]
                memory.touch_session(h, self.eng.state.get("name", "engagement"))
        except Exception:
            pass
        self.kb = Knowledge()
        self.weapons = Weapons(self.kb.roots)
        atomic_root = self.kb.roots.get("atomic")
        self.atomics = AtomicIndex(atomic_root) if atomic_root else None
        self._phase_order = phases or ["recon", "analyze", "plan", "report"]

    # ---------------- knowledge helpers ----------------
    def kb_hits(self, query, limit=6):
        hits = self.kb.search(query, limit=limit)
        return [f"[{h['corpus']}] {h['title']} — {h['rel']}" for h in hits]

    # ---------------- phases ----------------
    def phase_recon(self):
        self.eng.set_phase("recon")
        if self.mock:
            from urllib.parse import urlparse
            targets = []
            for s in self.scope.seeds:
                host = urlparse(s if "://" in s else "//" + s).hostname or s
                targets.append({
                    "host": host, "addrs": ["127.0.0.1"],
                    "ports": {80: None},
                    "urls": [{"url": s, "status": 200, "title": "mock",
                              "tech": []}],
                    "origins": [s], "intel": {}, "findings": []})
            self.eng.state["targets"] = targets
            self.eng.save()
            self.eng.log(f"recon(mock): {len(self.eng.state['targets'])} target(s)")
            return
        targets = run_recon(self.scope, self.scope.seeds,
                            wordlist=self.wordlist,
                            top_ports=self.top_ports, paths=self.paths,
                            osint=self.osint, log=self.eng.log)
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
        # lesson 20: fingerprint -> advisory mapping is an automatic step
        try:
            from .analysis import advisory_map
            offline = bool(os.environ.get("SHARDREAPER_OFFLINE"))
            advisory_map(self.eng, log=self.eng.log,
                         offline=offline or self.mock)
        except Exception as e:
            self.eng.log(f"advisory map skipped: {e}", "warn")
        # lesson 18: every injection theory gets a sink-contract record —
        # unverified until the cheapest oracle answers; the attack gate
        # refuses payload construction without a proven contract
        try:
            from .sink import new_contract
            sink_hints = {
                "ssti": ("ssti", "template"), "template": ("template",),
                "jinja": ("ssti", "template"), "twig": ("template",),
                "deserial": ("deser",), "unserialize": ("deser",),
            }
            existing = {(c.get("kind"), c.get("sink"))
                        for c in self.eng.state.get("sink_contracts", [])}
            for t in self.eng.state["targets"]:
                hint_words = list((t.get("intel") or {}).get("hints") or [])
                for u in t.get("urls", []):
                    tv = u.get("tech") or []
                    if isinstance(tv, str):
                        tv = [tv]
                    hint_words += tv
                hints = " ".join(hint_words)
                for marker, kinds in sink_hints.items():
                    if marker in hints.lower():
                        for kind in kinds:
                            if (kind, t["host"]) not in existing:
                                new_contract(self.eng, kind, t["host"],
                                             oracle="unset", status="unverified",
                                             reason="fingerprint hints at this "
                                             "sink — run `shardreaper sink` or "
                                             "read the render source first")
                                self.eng.log(f"sink contract {kind} @ "
                                             f"{t['host']}: unverified — no "
                                             f"payload until proven", "warn")
        except Exception as e:
            self.eng.log(f"sink contract pass skipped: {e}", "warn")
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
                                 "atomic": self._pick_atomic(["file and directory", "discovery"])})
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
                                 "atomic": self._pick_atomic(["wordlist scan", "web server"])})
        # LLM refinement when the brain is available
        if LLM.available() and not self.mock:
            self._llm_refine_plan(plan)
        self.eng.state["plan"] = plan
        self.eng.save()
        self.eng.log(f"plan: {len(plan)} items — {self._plan_severity_counts(plan)}")

    def _pick_atomic(self, keywords):
        if not self.atomics:
            return None
        # no platform filter: the target OS is unknown at plan time and dry-run
        # rendering is safe on any runner (powershell exec is blocked on linux)
        sel = self.atomics.select(keywords, platform=None, limit=3, strict=True)
        return [{"technique": s["technique"], "name": s["name"]} for s in sel]

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
            # lesson 19: every theory is tracked — a tombstoned theory is
            # never resurrected, and the refusal cites the recorded reason
            try:
                from . import hypothesis
                theory = f"{target}::{item['action']}"
                reason = hypothesis.tombstoned(target, theory)
                if reason:
                    self.eng.log(f"skip {theory}: TOMBSTONED — {reason}", "warn")
                    continue
                h = hypothesis.new_hypothesis(
                    self.eng, theory, host=target,
                    budget=item.get("budget", 3),
                    cutoff=item.get("cutoff", 3), detail=item["detail"])
            except Exception:
                h = None
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
                    # lesson 19 lifecycle: evidence extends the runway,
                    # a REAL probe without evidence spends budget + cutoff.
                    # A dry-run is not a probe — the budget is untouched.
                    if not r.get("dry_run"):
                        try:
                            if r.get("ok"):
                                hypothesis.note_evidence(
                                    self.eng, h["id"],
                                    f"{at['technique']} rc={r.get('returncode')} "
                                    f"{(r.get('stdout') or '')[:120]}")
                            else:
                                hypothesis.probe_failed(
                                    self.eng, h["id"],
                                    note=f"{at['technique']} {at['name']} "
                                         f"rc={r.get('returncode')}")
                        except Exception:
                            pass
                    # negative memory: tried without a confirmed finding — never re-waste it
                    if r.get("dry_run") or not r.get("ok"):
                        try:
                            from . import memory
                            memory.log_negative(target, at["technique"], at["name"])
                        except Exception:
                            pass
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
        kb = self.kb_hits(" ".join(kw[:3]), limit=6)
        for line in kb:
            self.eng.log(f"  KB  {line}", "action")
        if self.atomics:
            sel = self.atomics.select(kw, platform=None, limit=6, strict=True)
            for s in sel:
                self.eng.log(f"  AT  [{s['technique']}] {s['name']}", "action")
        wphases = TACTICAL_WEAPON_PHASES.get(key, phase)
        if not isinstance(wphases, list):
            wphases = [wphases]
        weapons = []
        for wp in wphases:
            weapons += self.weapons.by_phase(wp, limit=8)
        for w in weapons[:6]:
            self.eng.log(f"  WPN {w['name']} — {w['url']}", "action")
        self.eng.state["notes"].append({"ts": self.eng.state["updated"],
                                        "kind": f"tactical-{phase}",
                                        "kb": kb, "weapons": [w["name"] for w in weapons[:8]]})
        self.eng.save()

    def phase_spray(self):
        """Token spray (lessons 11+17): every held credential automatically
        fired against every authenticated surface on the box — kubelet,
        apiserver, registry, SSH, docker socket, stateful web logins (CSRF),
        git hosts, basic-auth APIs, databases, IMAP — with all protocol
        variants. The kubelet miss is the canonical case this phase exists
        to kill."""
        self.eng.set_phase("spray")
        from .spray import (load_credentials, spray, hit_severity,
                            discover_login_forms)
        from .http import OriginTransport
        creds = load_credentials(self.eng)
        if not creds:
            self.eng.log("spray: no held credentials — harvest first, then "
                         "re-run this phase", "warn")
            return
        transport = OriginTransport(timeout=10, insecure=True)
        # lesson 17: stateful web logins are surfaces — discover them first
        try:
            if not self.mock:
                discover_login_forms(self.eng, transport, log=self.eng.log)
        except Exception:
            pass
        self.eng.log(f"spray: {len(creds)} held credential(s) — firing against "
                     f"every authenticated surface", "action")
        result = spray(self.eng, creds, log=self.eng.log, ssh=not self.mock,
                       transport=transport)
        self.eng.state["spray"] = result
        for hit in result.get("hits", []):
            cred = hit.get("credential") or "unauthenticated"
            sev = hit_severity(hit)
            technique = "T1078 Valid Accounts" if hit.get("credential") \
                else "T1528 Steal Application Access Token"
            detail = (f"{hit['surface']} [{hit.get('status')}] "
                      f"{hit.get('class')} via {hit.get('form', 'anonymous')} "
                      f"cred={cred}")
            self.eng.log_action(technique=technique, target=hit["surface"],
                                detail=detail, outcome="confirmed",
                                evidence=[hit.get("label", "")[:160]])
            key = [hit["surface"], cred]
            if key not in self.eng.state.setdefault("spray_findings", []):
                self.eng.state["spray_findings"].append(key)
                self.eng.add_finding(
                    f"valid credential on {hit['surface']}", sev,
                    "credential-valid", technique, hit["surface"],
                    evidence=[detail], detail=detail,
                    impact="authenticated access to the target surface — "
                           "chain into exec/persistence immediately",
                    remediation="revoke/rotate the credential and audit its "
                                "use on every surface")
        self.eng.save()
        self.eng.log(f"spray: {len(result.get('hits', []))} hit(s) from "
                     f"{result.get('probes', 0)} probes", "win"
                     if result.get("hits") else "info")

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
            error = None
            try:
                if phase == "recon":
                    self.phase_recon()
                elif phase == "analyze":
                    self.phase_analyze()
                elif phase == "plan":
                    self.phase_plan()
                elif phase == "attack":
                    self.phase_attack()
                elif phase == "spray":
                    self.phase_spray()
                elif phase == "report":
                    self.phase_report()
                elif phase in PHASE_TECH_KEYWORDS:
                    self.phase_tactical(phase, phase)
                else:
                    self.eng.log(f"unknown phase {phase}", "err")
            except Exception as e:  # the ledger must checkpoint even on a crash
                error = f"{type(e).__name__}: {e}"
                self.eng.log(f"phase {phase} FAILED — {error}", "err")
            finally:
                self._checkpoint(phase, error=error)
        self.eng.log("engine complete")

    def _checkpoint(self, phase, error=None):
        """Post-Cobblestone lesson 10: checkpoint the ledger after every
        phase — including a phase that crashed. Full findings are persisted
        both to cross-engagement memory and to an engagement-local snapshot
        so a resumed run never re-proves a finding or re-wastes a technique."""
        try:
            from . import memory
            findings = self.eng.state.get("findings", [])
            proven = [{"id": f.get("id"), "severity": f.get("severity"),
                       "title": f.get("title", "")[:80]} for f in findings]
            full = [{"id": f.get("id"), "severity": f.get("severity"),
                     "class": f.get("class"), "title": f.get("title", "")[:80],
                     "target": f.get("target"),
                     "technique": f.get("technique")} for f in findings]
            ruled = sorted({a.get("technique") for a in
                            self.eng.state.get("actions", [])
                            if a.get("outcome") in ("dry-run", "planned", "failed")})
            open_items = [p.get("action") for p in
                          self.eng.state.get("plan", [])][:12]
            creds = self.eng.state.get("credentials", [])
            memory.checkpoint(self.eng.state.get("name", "engagement"), phase,
                              proven, ruled, open_items, findings=full)
            snap_dir = os.path.join(self.base, "checkpoints")
            os.makedirs(snap_dir, exist_ok=True)
            snap = {"phase": phase, "error": error, "findings": full,
                    "ruled_out": ruled, "open": open_items,
                    "credentials": len(creds),
                    "updated": self.eng.state.get("updated")}
            with open(os.path.join(snap_dir, f"{phase}.json"), "w",
                      encoding="utf-8") as f:
                json.dump(snap, f, indent=1)
        except Exception:
            pass


def engage(base, name, seeds, in_scope, out_of_scope, objective="", mock=False):
    os.makedirs(base, exist_ok=True)
    scope_path = os.path.join(base, "scope.json")
    with open(scope_path, "w", encoding="utf-8") as f:
        json.dump({"name": name, "in_scope": in_scope or [],
                   "out_of_scope": out_of_scope or [], "seeds": seeds or []}, f, indent=2)
    scope = Scope(in_scope, out_of_scope, seeds, name)
    eng = Engagement(base, name, scope_path)
    eng.state["seeds"] = seeds or []
    if objective:
        eng.state["objective"] = objective
    eng.save()
    eng.log(f"engagement created: {base} (scope: {len(in_scope or [])} in / "
            f"{len(out_of_scope or [])} out / {len(seeds or [])} seeds)")
    # loud pre-flight warnings — the operator owns the scope, the agent obeys it
    if not in_scope:
        eng.log("WARNING: no in-scope rules — everything is DENIED (default deny)", "warn")
    if not seeds:
        eng.log("WARNING: no seeds — recon has nothing to start from", "warn")
    for seed in seeds or []:
        if not scope.in_scope_host(seed):
            eng.log(f"WARNING: seed {seed} is OUT of scope — recon will skip it", "warn")
    # post-Cobblestone lesson 7: prove the local arsenal works before the run
    if not os.environ.get("SHARDREAPER_SKIP_ENVCHECK"):
        try:
            from .envcheck import arsenal_report, format_report
            report = arsenal_report(base=base)
            eng.state["notes"].append({"ts": eng.state["updated"],
                                       "kind": "arsenal", "data": report})
            eng.save()
            eng.log(f"arsenal self-check: {len(report['ok_tools'])} working / "
                    f"{len(report['dead_tools'])} dead tools — "
                    f"{'hashcat usable' if report['hashcat_opencl']['opencl'] else 'hashcat DEAD (use shardreaper crack)'}",
                    "warn" if report["dead_tools"] else "info")
        except Exception:
            pass
    print()
    print(scope.describe())
    return base


def cli_engage(args):
    engage(args.dir, args.name, args.seeds or [], args.in_scope or [],
           args.out_of_scope or [], args.objective, args.mock)


def cli_run(args):
    base = os.path.abspath(args.dir)
    if not os.path.isfile(os.path.join(base, "state.json")):
        print(f"no engagement at {base} — run: shardreaper engage ...")
        return 1
    phases = [p.strip() for p in args.phases.split(",") if p.strip()] if args.phases \
        else ["recon", "analyze", "plan", "report"]
    bad = [p for p in phases if p not in PHASES]
    if bad:
        print(f"unknown phase(s): {', '.join(bad)} — valid: {', '.join(PHASES)}")
        return 2
    eng = Engine(base, phases=phases, go=args.go, mock=args.mock,
                 wordlist=args.wordlist, top_ports=args.top_ports,
                 paths=not args.no_paths, osint=not args.no_osint)
    eng.run()
    return 0


def cli_autopilot(args):
    """Autonomous loop: resume where the engagement left off and drive to report.

    Checkpoints: --paranoid after every phase (default) · --normal after attack
    · --yolo none. Non-TTY stdin skips prompts so pipelines stay safe. The
    scope gate stays on for every phase regardless of mode.
    """
    import sys as _sys
    base = os.path.abspath(args.dir)
    if not os.path.isfile(os.path.join(base, "state.json")):
        print(f"no engagement at {base} — run: shardreaper engage ...")
        return 1
    eng = Engagement.load(base)
    cur = eng.phase if eng.phase in PHASES else "engage"
    remaining = PHASES[PHASES.index(cur):]
    if args.phases:
        remaining = [p.strip() for p in args.phases.split(",") if p.strip()]
    interactive = _sys.stdin.isatty() and not args.yes
    checkpoint = {"paranoid": "all", "normal": "attack", "yolo": "none"}[args.mode]
    print(f"autopilot [{args.mode}] — phases: {', '.join(remaining)}")
    for phase in remaining:
        e = Engine(base, phases=[phase], go=args.go, mock=args.mock)
        e.run()
        if interactive and (checkpoint == "all" or
                            (checkpoint == "attack" and phase in ("attack", "report"))):
            try:
                a = input(f"[autopilot] continue after {phase}? [Enter=yes / q=stop] ")
            except (EOFError, KeyboardInterrupt):
                a = "q"
            if a.strip().lower() == "q":
                print("autopilot stopped by operator")
                return 0
    return 0


def cli_hunt(args):
    """BugHunter-style engagement scaffolder: scope.md + structured folders.

    Invoking /hunt asserts the operator holds authorization for the named
    scope. The deliverable is a reproducible, remediable finding; an
    out-of-scope host stops the run rather than widening it.
    """
    base = os.path.abspath(args.dir)
    os.makedirs(base, exist_ok=True)
    for sub in ("findings", "evidence", "recon", "reports"):
        os.makedirs(os.path.join(base, sub), exist_ok=True)
    scope_md = os.path.join(base, "scope.md")
    with open(scope_md, "w", encoding="utf-8") as f:
        f.write("# Scope — {name}\n\n## In scope\n\n{p}\n## Out of scope\n\n{p}\n"
                "## Seeds\n\n{p}\n".format(
                    name=args.name, p="* (paste patterns here — e.g. example.com, 10.0.0.0/24)"))
    scope_json = os.path.join(base, "scope.json")
    with open(scope_json, "w", encoding="utf-8") as f:
        json.dump({"name": args.name, "in_scope": args.in_scope or [],
                   "out_of_scope": args.out_of_scope or [],
                   "seeds": args.seeds or []}, f, indent=2)
    eng = Engagement(base, args.name, scope_json)
    eng.state["seeds"] = args.seeds or []
    if args.objective:
        eng.state["objective"] = args.objective
    eng.save()
    mode = args.mode
    eng.log(f"hunt scaffold ready [{mode}] — fill scope.md, then: "
            f"shardreaper run {base} --phases recon,analyze,plan,attack,report")
    with open(os.path.join(base, "notes.md"), "w", encoding="utf-8") as f:
        f.write(f"# {args.name} — operator notes\n\n"
                f"engagement frame: authorized assessment of the scope in scope.md\n"
                f"mode: {mode}\nobjective: {args.objective or '(not set)'}\n")
    print()
    print(f"engagement assertion: the operator holds written authorization for "
          f"the named scope — {mode} mode.")
    print(f"scaffold: {base}")
    print(f"  scope.md   <- fill the in/out patterns (BugHunter-compatible)")
    print(f"  findings/ evidence/ recon/ reports/   <- structured workspace")
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
                    "escalate,persist,move,harvest,spray,evade,exfil,report")
    rp.add_argument("--go", action="store_true", help="EXECUTE atomic tests (default dry-run)")
    rp.add_argument("--mock", action="store_true")
    rp.add_argument("--wordlist", default=None, help="subdomain wordlist (default: builtin)")
    rp.add_argument("--top-ports", type=int, default=100)
    rp.add_argument("--no-paths", action="store_true", help="skip sensitive-path probing")
    rp.add_argument("--no-osint", action="store_true", help="skip passive scope expansion")
    rp.set_defaults(fn=cli_run)

    ap = sub.add_parser("autopilot", help="autonomous loop to report, with checkpoints")
    ap.add_argument("dir", help="engagement folder")
    ap.add_argument("--phases", default="", help="override phases (default: resume from state)")
    ap.add_argument("--mode", default="paranoid", choices=["paranoid", "normal", "yolo"],
                    help="checkpoint density")
    ap.add_argument("--go", action="store_true")
    ap.add_argument("--mock", action="store_true")
    ap.add_argument("--yes", action="store_true", help="skip prompts (non-interactive)")
    ap.set_defaults(fn=cli_autopilot)

    hp = sub.add_parser("hunt", help="rich engagement scaffold (scope.md + workspace)")
    hp.add_argument("dir", help="engagement folder")
    hp.add_argument("--name", default="engagement")
    hp.add_argument("--seeds", action="append", default=[])
    hp.add_argument("--in-scope", action="append", default=[])
    hp.add_argument("--out-of-scope", action="append", default=[])
    hp.add_argument("--objective", default="")
    hp.add_argument("--mode", default="red-team", choices=["red-team", "wapt"])
    hp.set_defaults(fn=cli_hunt)

    sp = sub.add_parser("status", help="engagement status")
    sp.add_argument("dir")
    sp.set_defaults(fn=cli_status)
    return sub
