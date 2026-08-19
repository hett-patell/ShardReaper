#!/usr/bin/env python3
"""
atomics.py — Atomic Red Team integration.

Indexes the 343 local ATT&CK technique files (1,800+ executable tests),
selects tests by technique/platform/keyword, renders their commands with
input arguments resolved, and runs them. Dry-run by default; live execution
requires an explicit --go. This turns the corpus into ShardReaper's weapons rack.

Technique index: atomics/<T>/<T>.yaml — each holds `atomic_tests[]` with
`executor.command` (and optional cleanup_command), input_arguments with
defaults, supported_platforms, and dependency checks.
"""
import json
import os
import re
import subprocess

try:
    import yaml as _yaml
    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

PLATFORM_SHORTHAND = {
    "linux": "linux", "windows": "windows", "macos": "macos",
    "iaas:aws": "aws", "iaas:azure": "azure", "iaas:gcp": "gcp",
    "containers": "container", "office-365": "o365", "saas": "saas",
    "iaas": "iaas",
}


def _mini_yaml(text):
    """Fallback parser for atomic YAMLs when PyYAML is absent.

    Extracts the fields ShardReaper actually uses: technique id, display_name,
    test names, platforms, descriptions, and executor commands.
    """
    import json
    out = {"attack_technique": "", "display_name": "", "atomic_tests": []}
    m = re.search(r"^attack_technique:\s*(\S+)", text, re.M)
    if m:
        out["attack_technique"] = m.group(1)
    m = re.search(r"^display_name:\s*['\"]?(.+?)['\"]?\s*$", text, re.M)
    if m:
        out["display_name"] = m.group(1).strip()
    # split test blocks
    blocks = re.split(r"^-\s*name:\s*", text, flags=re.M)[1:]
    for b in blocks:
        test = {"name": b.splitlines()[0].strip().strip("'\""),
                "description": "", "supported_platforms": [], "input_arguments": {},
                "executor": {"name": "", "command": "", "cleanup_command": ""},
                "dependencies": []}
        m = re.search(r"description:\s*\|-?\n((?:[ \t]+.*\n?)+)", b)
        if m:
            test["description"] = "\n".join(l.strip() for l in m.group(1).splitlines())[:400]
        test["supported_platforms"] = [
            m2 for m2 in re.findall(r"^  -\s+(\S+)$", b, re.M) if ":" not in m2]
        m = re.search(r"executor:\s*\n\s*name:\s*(\S+)", b)
        if m:
            test["executor"]["name"] = m.group(1)
        m = re.search(r"command:\s*\|-?\n((?:[ \t]+.*\n?)+)", b)
        if m:
            test["executor"]["command"] = "\n".join(l.strip() for l in m.group(1).splitlines())
        m = re.search(r"cleanup_command:\s*\|-?\n((?:[ \t]+.*\n?)+)", b)
        if m:
            test["executor"]["cleanup_command"] = "\n".join(l.strip() for l in m.group(1).splitlines())
        m = re.search(r"input_arguments:\n((?:[ \t]+.*\n?)+?)(?=\n\s{2}\S|\Z)", b)
        if m:
            for am in re.finditer(r"^\s{4}(\w+):\s*\n\s+description:.*?\n\s+type:\s*(\S+).*?\n\s+default:\s*(.+)$",
                                  m.group(1), re.M | re.S):
                try:
                    val = json.loads(am.group(3).strip())
                except Exception:
                    val = am.group(3).strip().strip("'\"")
                test["input_arguments"][am.group(1)] = {"type": am.group(2), "default": val}
        out["atomic_tests"].append(test)
    return out


class AtomicIndex:
    def __init__(self, atomic_root):
        self.root = atomic_root
        self._techs = None
        self._loaded_at = None

    # ---------------- indexing ----------------
    def _load(self):
        if self._techs is not None:
            return self._techs
        techs = {}
        atomics_dir = os.path.join(self.root, "atomics")
        if not os.path.isdir(atomics_dir):
            return techs
        for tech_id in sorted(os.listdir(atomics_dir)):
            d = os.path.join(atomics_dir, tech_id)
            if not os.path.isdir(d):
                continue
            yf = os.path.join(d, tech_id + ".yaml")
            if not os.path.isfile(yf):
                continue
            try:
                text = open(yf, "r", encoding="utf-8", errors="ignore").read()
                if HAVE_YAML:
                    data = _yaml.safe_load(text) or {}
                else:
                    data = _mini_yaml(text)
                tests = data.get("atomic_tests") or []
                techs[tech_id] = {
                    "id": tech_id,
                    "display_name": data.get("display_name", tech_id),
                    "path": yf,
                    "tests": tests,
                }
            except Exception:
                continue
        self._techs = techs
        return techs

    @property
    def technique_ids(self):
        return sorted(self._load().keys())

    def count(self):
        d = self._load()
        return len(d), sum(len(t["tests"]) for t in d.values())

    def get(self, tech_id):
        return self._load().get(tech_id.upper())

    def search(self, query, limit=15):
        q = query.lower()
        qtoks = set(re.findall(r"[a-z0-9]+", q))
        scored = []
        for tid, tech in self._load().items():
            hay = f"{tid} {tech['display_name']}".lower()
            score = 0
            for tok in qtoks:
                if tok in hay:
                    score += 2
            for t in tech["tests"]:
                if any(tok in (t.get("name") or "").lower() for tok in qtoks):
                    score += 1
            if score:
                scored.append((score, tid, tech["display_name"]))
        scored.sort(key=lambda x: (-x[0], x[1]))
        return [{"id": t, "name": n, "score": s} for s, t, n in scored[:limit]]

    def select(self, keywords=None, platform=None, limit=12, strict=False):
        """Pick the most relevant tests for a phase/keyword + host platform.

        strict=True counts only test-name and technique-name matches (no
        description hits) — used by the engine so generic words like "web"
        cannot drag in loosely-related tests. Multi-word keywords are treated
        as phrases (higher weight); single words match on word boundaries.
        """
        kw = [k.lower() for k in (keywords or [])]
        phrases = [k for k in kw if " " in k]
        singles = [k for k in kw if " " not in k]
        picked = []
        for tid, tech in self._load().items():
            tname = tech["display_name"].lower()
            for t in tech["tests"]:
                name = (t.get("name") or "").lower()
                desc = (t.get("description") or "").lower()
                if platform and not self._platform_ok(t, platform):
                    continue
                if not kw:
                    picked.append((0, tid, t))
                    continue
                s = 0
                for p in phrases:
                    if p in name:
                        s += 4
                    elif p in tname:
                        s += 3
                for k in singles:
                    pat = re.compile(r"\b" + re.escape(k) + r"\b")
                    if pat.search(name):
                        s += 3
                    elif pat.search(tname):
                        s += 2
                    elif not strict and k in desc:
                        s += 1
                if s:
                    picked.append((s, tid, t))
        picked.sort(key=lambda x: (-x[0], x[1]))
        out = []
        for s, tid, t in picked[:limit]:
            out.append({
                "technique": tid, "technique_name": self.get(tid)["display_name"],
                "name": t.get("name"), "platforms": t.get("supported_platforms"),
                "executor": (t.get("executor") or {}).get("name"),
                "description": (t.get("description") or "")[:200],
                "score": s,
            })
        return out

    @staticmethod
    def _platform_ok(test, platform):
        plats = [p.lower() for p in (test.get("supported_platforms") or [])]
        if not plats:
            return True
        wanted = PLATFORM_SHORTHAND.get(platform, platform)
        for p in plats:
            if p == platform or p == wanted or p.split(":")[-1] == wanted:
                return True
        return False

    # ---------------- rendering ----------------
    def render_command(self, test, inputs=None, cleanup=False, atomics_path=None):
        """Resolve #{arg} placeholders from input defaults and clean paths."""
        cmd = test.get("executor") or {}
        text = (cmd.get("cleanup_command") if cleanup else cmd.get("command")) or ""
        args = {k: (v or {}).get("default") for k, v in (test.get("input_arguments") or {}).items()}
        if inputs:
            args.update(inputs)
        for k, v in args.items():
            if v is None:
                v = ""
            text = text.replace(f"#{{{k}}}", str(v))
        if atomics_path:
            text = text.replace("PathToAtomicsFolder", atomics_path)
        return text.strip()

    # ---------------- execution ----------------
    def run_test(self, test, inputs=None, atomics_path=None, dry_run=True,
                 timeout=120, cleanup=False):
        cmd = self.render_command(test, inputs, cleanup, atomics_path)
        executor = (test.get("executor") or {}).get("name") or "sh"
        if not cmd:
            return {"ok": False, "error": "empty command", "cmd": ""}
        if dry_run:
            return {"ok": True, "dry_run": True, "cmd": cmd, "executor": executor,
                    "note": "dry-run: pass --go to execute"}
        shell = {"sh": "sh -c", "bash": "bash -c", "command_prompt": "cmd /c",
                 "manual": None, "powershell": "powershell -NoProfile -Command",
                 "pwsh": "pwsh -NoProfile -Command", "python": "python3 -c"}.get(executor)
        if executor in ("powershell", "pwsh") and os.name != "nt":
            return {"ok": False, "error": "powershell executor needs a Windows host",
                    "cmd": cmd}
        if shell is None:
            return {"ok": False, "error": f"executor '{executor}' requires manual execution",
                    "cmd": cmd}
        try:
            p = subprocess.run(shell.split() + [cmd], capture_output=True, text=True,
                               timeout=timeout, shell=False)
            return {"ok": p.returncode == 0, "cmd": cmd, "executor": executor,
                    "returncode": p.returncode,
                    "stdout": (p.stdout or "")[-2000:],
                    "stderr": (p.stderr or "")[-2000:]}
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": "timeout", "cmd": cmd}
        except OSError as e:
            return {"ok": False, "error": f"exec:{e}", "cmd": cmd}


def cli_list(args):
    idx = AtomicIndex(args.root)
    n_tech, n_tests = idx.count()
    print(f"atomic index: {n_tech} techniques / {n_tests} tests @ {args.root}")
    if args.search:
        for r in idx.search(args.search, limit=args.limit):
            print(f"  {r['id']:10s} {r['name']}")
    else:
        for tid in idx.technique_ids:
            print(f"  {tid:10s} {idx.get(tid)['display_name']}")


def cli_select(args):
    idx = AtomicIndex(args.root)
    if args.technique:
        tech = idx.get(args.technique)
        if not tech:
            print(f"technique {args.technique} not in index")
            return 1
        tests = [{"technique": tech["id"], "technique_name": tech["display_name"],
                  "name": t.get("name"), "platforms": t.get("supported_platforms"),
                  "executor": (t.get("executor") or {}).get("name"),
                  "description": (t.get("description") or "")[:180]} for t in tech["tests"]]
    else:
        tests = idx.select(args.keywords or [], args.platform, limit=args.limit)
    for i, t in enumerate(tests):
        print(f"[{i}] {t['technique']} {t['name']}  (executor={t['executor']}, "
              f"platforms={','.join(t['platforms'] or [])})")
        if t.get("description"):
            print(f"    {t['description'][:150]}")
    print("\nrun: shardreaper atomic run <idx> --go")


def cli_run(args, idx=None):
    idx = idx or AtomicIndex(args.root)
    tests = None
    if args.technique:
        tech = idx.get(args.technique)
        tests = tech["tests"] if tech else []
    elif args.index is not None:
        sel = idx.select(args.keywords or [], args.platform, limit=args.limit)
        if 0 <= args.index < len(sel):
            tech = idx.get(sel[args.index]["technique"])
            tests = [t for t in tech["tests"] if t.get("name") == sel[args.index]["name"]]
    if not tests:
        print("no test selected — use --technique T#### or --index N (see: shardreaper atomic select)")
        return 1
    test = tests[0]
    r = idx.run_test(test, atomics_path=os.path.join(args.root, "atomics"),
                     dry_run=not args.go, timeout=args.timeout, cleanup=args.cleanup)
    print(f"technique: {test.get('name')}")
    print(f"executor : {r.get('executor')}")
    print("-" * 60)
    print(r.get("cmd", ""))
    print("-" * 60)
    if r.get("dry_run"):
        print(r["note"])
        return 0
    if r.get("error"):
        print(f"ERROR: {r['error']}")
        return 1
    print(f"returncode: {r.get('returncode')}")
    if r.get("stdout"):
        print("stdout:")
        print(r["stdout"])
    if r.get("stderr"):
        print("stderr:")
        print(r["stderr"])
    return 0


def _default_root():
    from .knowledge import corpus_roots
    roots = corpus_roots()
    return roots.get("atomic", os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "..",
        "atomic-red-team"))


def build_navigator_layer(eng, title=None):
    """ATT&CK Navigator layer from an engagement: planned + executed techniques."""
    from collections import Counter
    counts = Counter()
    for a in eng.state.get("actions", []):
        tid = str(a.get("technique", ""))
        m = re.match(r"^(T\d{4}(?:\.\d{3})?)", tid)
        if m:
            counts[m.group(1)] += 1
    for p in eng.state.get("plan", []):
        tid = str(p.get("technique", ""))
        m = re.match(r"^(T\d{4}(?:\.\d{3})?)", tid)
        if m:
            counts.setdefault(m.group(1), 0)
    techniques = []
    for tid, n in sorted(counts.items()):
        techniques.append({
            "techniqueID": tid,
            "score": min(n or 1, 10),
            "comment": f"ShardReaper: {n} action(s)" if n else "ShardReaper: planned",
            "enabled": True,
        })
    return {
        "name": title or f"ShardReaper — {eng.state.get('name', 'engagement')}",
        "versions": {"attack": "18", "navigator": "5.3.0", "layer": "4.5"},
        "description": "Techniques planned/executed by ShardReaper during this engagement.",
        "domain": "enterprise-attack",
        "filters": {"platforms": ["Windows", "Linux", "macOS"]},
        "gradient": {"colors": ["#ffffff", "#ce232e"], "minValue": 0, "maxValue": 10},
        "legendItems": [
            {"label": "executed", "color": "#ce232e"},
            {"label": "planned", "color": "#f7b267"}],
        "techniques": techniques,
    }


def cli_navigator(args):
    if args.list:
        bundled = os.path.join(_default_root(), "atomics", "Indexes",
                               "Attack-Navigator-Layers")
        if os.path.isdir(bundled):
            print("bundled platform layers:")
            for f in sorted(os.listdir(bundled)):
                print(f"  {f}")
        else:
            print("no bundled layers found")
        return 0
    from .state import Engagement
    base = os.path.abspath(args.dir)
    if not os.path.isfile(os.path.join(base, "state.json")):
        print(f"no engagement at {base}")
        return 1
    eng = Engagement.load(base)
    layer = build_navigator_layer(eng)
    out = os.path.join(base, "navigator-layer.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(layer, f, indent=1)
    print(f"navigator layer written: {out} ({len(layer['techniques'])} technique(s)) "
          f"— upload to https://mitre-attack.github.io/attack-navigator/")
    return 0


def build_arg_parser(sub):
    p = sub.add_parser("atomic", help="Atomic Red Team weapons rack")
    subp = p.add_subparsers(dest="cmd", required=True)
    lp = subp.add_parser("list", help="list techniques (or search)")
    lp.add_argument("--root", default=_default_root())
    lp.add_argument("--search")
    lp.add_argument("--limit", type=int, default=30)
    lp.set_defaults(fn=cli_list)
    sp = subp.add_parser("select", help="select tests by technique/keyword/platform")
    sp.add_argument("--root", default=_default_root())
    sp.add_argument("--technique", help="ATT&CK id, e.g. T1003")
    sp.add_argument("keywords", nargs="*")
    sp.add_argument("--platform", default=None)
    sp.add_argument("--limit", type=int, default=12)
    sp.set_defaults(fn=cli_select)
    rp = subp.add_parser("run", help="render/execute one test (dry-run by default)")
    rp.add_argument("--root", default=_default_root())
    rp.add_argument("--technique", help="ATT&CK id")
    rp.add_argument("--index", type=int, help="index from `select`")
    rp.add_argument("keywords", nargs="*")
    rp.add_argument("--platform", default=None)
    rp.add_argument("--limit", type=int, default=12)
    rp.add_argument("--go", action="store_true", help="actually execute (default: dry-run)")
    rp.add_argument("--cleanup", action="store_true", help="render/run cleanup command")
    rp.add_argument("--timeout", type=int, default=120)
    rp.set_defaults(fn=cli_run)
    np_ = subp.add_parser("navigator", help="ATT&CK Navigator layer from an engagement")
    np_.add_argument("dir", nargs="?", default=None, help="engagement folder")
    np_.add_argument("--list", action="store_true", help="list bundled platform layers")
    np_.set_defaults(fn=cli_navigator)
    return p
