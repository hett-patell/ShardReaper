#!/usr/bin/env python3
"""
envcheck.py — the arsenal self-check.

Post-Cobblestone lesson 7: "709 weapons live offline" did not mean working
weapons — hashcat arrived as a pip wheel with no OpenCL and read-only state
dirs. Now every engagement starts with a deterministic probe of the local
rack: which tools exist, which ones actually RUN, whether the pure-python
fallbacks are available, and whether the state dirs are writable.
"""
import json
import os
import shutil
import subprocess
import sys

# (tool, probe args, rc-means-ok, note)
TOOL_PROBES = [
    ("nmap", ["--version"], 0, "port/service scanning"),
    ("masscan", ["--version"], 0, "high-speed port scanning"),
    ("nuclei", ["-version"], 0, "template scanning"),
    ("ffuf", ["-V"], 0, "web fuzzing"),
    ("gobuster", ["--version"], 0, "content discovery"),
    ("sqlmap", ["--version"], 0, "SQLi automation"),
    ("hydra", ["-h"], 0, "network logon brute"),
    ("john", ["--version"], 0, "password cracking"),
    ("hashcat", ["--version"], 0, "GPU password cracking"),
    ("impacket-secretsdump", ["-h"], 0, "AD credential dump"),
    ("evil-winrm", ["--version"], 0, "WinRM shell"),
    ("nxc", ["--version"], 0, "AD swiss-army (NetExec)"),
    ("bloodhound-python", ["--version"], 0, "AD path collection"),
    ("subfinder", ["-version"], 0, "passive subdomain enum"),
    ("chisel", ["--version"], 0, "TCP/UDP tunneling"),
    ("openssl", ["version"], 0, "TLS/crypto toolkit"),
]


def probe_tool(name, args):
    path = shutil.which(name)
    if not path:
        return {"name": name, "status": "missing"}
    try:
        p = subprocess.run([path] + args, capture_output=True, text=True,
                           timeout=10)
        return {"name": name, "status": "ok" if p.returncode == 0 else "broken",
                "path": path, "note": (p.stderr or p.stdout or "").strip()[:120]}
    except (subprocess.TimeoutExpired, OSError) as e:
        return {"name": name, "status": "broken", "path": path, "note": str(e)[:120]}


def hashcat_opencl():
    """Does hashcat actually have a usable backend? (--version is not enough.)"""
    r = probe_tool("hashcat", ["-I"])
    if r["status"] == "ok":
        return {"opencl": True, "detail": (r.get("note") or "")[:160]}
    return {"opencl": False, "detail": "hashcat -I failed — treat hashcat as DEAD "
            "and use `shardreaper crack` (pure-python $1$/$5$/$6$) instead"}


def python_fallbacks():
    out = {}
    for mod in ("bcrypt", "requests", "yaml", "cryptography"):
        try:
            __import__(mod)
            out[mod] = "ok"
        except ImportError:
            out[mod] = "missing"
    out["pure-crack"] = "ok ($1$/$5$/$6$ + raw digests, stdlib-only)"
    return out


def writable_dirs(paths):
    out = {}
    for label, p in paths:
        try:
            os.makedirs(p, exist_ok=True)
            probe = os.path.join(p, ".shardreaper-write-probe")
            with open(probe, "w") as f:
                f.write("x")
            os.remove(probe)
            out[label] = "writable"
        except OSError:
            out[label] = "READ-ONLY (state will not persist)"
    return out


def arsenal_report(base=None, state_dirs=None):
    """Full self-check. Returns a dict — never raises."""
    report = {
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "tools": [probe_tool(n, a) for n, a, _rc, _d in TOOL_PROBES],
        "hashcat_opencl": hashcat_opencl(),
        "fallbacks": python_fallbacks(),
        "state_dirs": writable_dirs(state_dirs or [
            ("engagement", base or "."),
            ("data", os.path.join(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))), "data")),
        ]),
    }
    report["ok_tools"] = [t["name"] for t in report["tools"] if t["status"] == "ok"]
    report["dead_tools"] = [t["name"] for t in report["tools"] if t["status"] != "ok"]
    return report


def format_report(report):
    lines = ["ARSENAL SELF-CHECK",
             f"  python {report['python']} on {report['platform']}"]
    lines.append(f"  working tools ({len(report['ok_tools'])}): "
                 f"{', '.join(report['ok_tools']) or 'NONE'}")
    if report["dead_tools"]:
        lines.append(f"  missing/broken ({len(report['dead_tools'])}): "
                     f"{', '.join(report['dead_tools'])}")
    for t in report["tools"]:
        if t["status"] == "broken":
            lines.append(f"    BROKEN {t['name']}: {t.get('note', '')[:80]}")
    lines.append(f"  hashcat: {'usable' if report['hashcat_opencl']['opencl'] else 'DEAD — use shardreaper crack'}")
    lines.append(f"  fallbacks: {', '.join(f'{k}={v}' for k, v in report['fallbacks'].items())}")
    for label, st in report["state_dirs"].items():
        lines.append(f"  {label}: {st}")
    return "\n".join(lines)


def cli_arsenal(args):
    report = arsenal_report(base=args.dir)
    print(format_report(report))
    if args.dir:
        out = os.path.join(os.path.abspath(args.dir), "arsenal.json")
        try:
            with open(out, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=1)
            print(f"report written: {out}")
        except OSError as e:
            print(f"could not write {out}: {e}")
    return 0


def build_arg_parser(sub):
    p = sub.add_parser("arsenal", help="environment self-check: which tools "
                        "actually work, fallbacks, state dirs")
    p.add_argument("--dir", default=None, help="engagement dir (writes arsenal.json)")
    p.set_defaults(fn=cli_arsenal)
    return p
