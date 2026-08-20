#!/usr/bin/env python3
"""
priv.py — root escalation is a dataflow problem (lesson 22).

The general pattern that roots boxes: a ROOT-RUN periodic consumer
(cron / systemd timer / CI / git hook / log processor / file watcher) reads
ATTACKER-INFLUENCEABLE input (repo content, filenames, uploads, config)
through a path-join or command-construction bug. Blind guessing wastes the
clock; the dataflow audit does not:

1. INVENTORY the privileged consumers: /etc/crontab, /etc/cron.d, the
   cron.{daily,hourly,weekly,monthly} dirs, user crontabs, systemd timers
   (and the units they trigger).
2. TRACE their input sources: which commands touch attacker-influenceable
   paths (repo checkouts, /tmp, /var/www, upload dirs, log files) and how
   (cp/mv/rm/read/path-join in scripts).
3. TEST the path contract with canary names: absolute paths, `..`
   components, path separators, glob metacharacters — the exact corpus of
   names that a path-join bug trips on.

`exec_one` is any command transport (local subprocess, kubelet exec, ssh) —
the audit runs wherever the target box is reachable.
"""
import os
import re
import subprocess

CRON_PATHS = ["/etc/crontab", "/etc/cron.d", "/etc/cron.daily",
              "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly",
              "/etc/anacrontab", "/var/spool/cron/crontabs"]

# attacker-influenceable locations whose content/filenames an attacker can
# drive — the input side of the priv-esc dataflow
ATTACKER_INPUTS = [
    "/tmp", "/var/tmp", "/dev/shm", "/var/www", "/srv", "/opt/backups",
    "/var/log", "/home", "/root/repos", "/git", "/uploads", "/var/lib/jenkins",
    "/var/run", "/run", ".",
]

DANGEROUS_OPS = [("path-join", r"\b(?:cp|mv|ln|cat|source|\.|bash|sh)\s+"
                  r"[^\n]*\$[A-Za-z_][A-Za-z0-9_]*"),
                 ("command-sub", r"\$\(|\`"),
                 ("tar-wildcard", r"\btar\b[^\n]*\*"),
                 ("rsync", r"\brsync\b"),
                 ("unquoted-glob", r"\b(?:cp|mv|rm)\s+[^\s\"']*\*"),
                 ("eval", r"\beval\b"),
                 ("find-exec", r"\bfind\b[^\n]*\-exec"),
                 ("git-hook", r"\b(?:pre-commit|post-receive|post-merge|"
                  r"post-checkout|update)\b"),
                 ("script-exec", r"\b(?:python|ruby|perl|php|node)\s+\S+")]


def _split_user_cmd(rest):
    """(user, command) from the tail of a cron line. A leading
    path/~/./command word means a USER crontab (no user column)."""
    rp = (rest or "").split(None, 1)
    if not rp:
        return "root", ""
    if len(rp) == 1 or rp[0].startswith(("/", ".", "~")) or "/" in rp[0]:
        return "root", rest
    return rp[0], (rp[1] if len(rp) > 1 else "")


def parse_cron(text, source="crontab"):
    """Parse crontab content -> jobs. Handles /etc/crontab style (user
    column) AND user crontabs (no user column — command starts with a
    path)."""
    jobs = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if re.match(r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*=", line):
            continue  # env assignment
        if line.startswith("@"):
            parts = line.split(None, 1)
            if len(parts) < 2:
                continue
            user, command = _split_user_cmd(parts[1])
            jobs.append({"schedule": parts[0], "user": user,
                         "command": command.strip(), "source": source})
            continue
        parts = line.split(None, 5)
        if len(parts) < 6:
            continue
        user, command = _split_user_cmd(parts[5])
        jobs.append({"schedule": " ".join(parts[:5]), "user": user,
                     "command": command.strip(), "source": source})
    return jobs


def parse_systemctl(text):
    """systemctl list-timers output -> timer rows."""
    rows = []
    for line in (text or "").splitlines():
        m = re.match(r"^(\S+)\s+\S+\s+(\S+)\s+(\S+\s+\S+)\s+(\S+)", line)
        if m:
            rows.append({"timer": m.group(1), "next": m.group(2),
                         "left": m.group(3), "passes": m.group(4),
                         "unit": m.group(1).replace(".timer", ".service")})
    return rows


def local_exec_one(cmd, timeout=10):
    """Local transport — used when the agent runs ON the box."""
    try:
        p = subprocess.run(["sh", "-c", cmd], capture_output=True,
                           text=True, timeout=timeout)
        return (p.stdout or "", p.stderr or "", p.returncode == 0)
    except (subprocess.TimeoutExpired, OSError) as e:
        return "", str(e), False


def inventory_timers(exec_one=None):
    """Privileged periodic consumers on the box. Returns a report dict."""
    exec_one = exec_one or local_exec_one
    out = {"cron_files": {}, "crontabs": {}, "systemd": [], "jobs": []}
    for path in CRON_PATHS:
        if not os.path.exists(path) and path.startswith("/etc"):
            so, _, ok = exec_one(f"ls {path} 2>/dev/null || true")
            names = [path] if ok and path.endswith(("crontab", "anacrontab")) \
                else [n for n in so.split() if n]
        else:
            names = [path] if os.path.isfile(path) else []
        for name in names:
            try:
                so, _, _ = exec_one(f"cat {name} 2>/dev/null || true")
                out["cron_files"][name] = so[:4000]
            except Exception:
                pass
    for who in ("root",):
        so, _, _ = exec_one(f"crontab -l -u {who} 2>/dev/null || true")
        if so.strip():
            out["crontabs"][who] = so[:4000]
    so, _, _ = exec_one("systemctl list-timers --all --no-pager 2>/dev/null "
                        "|| true")
    out["systemd"] = parse_systemctl(so)
    for path, text in out["cron_files"].items():
        out["jobs"] += parse_cron(text, source=path)
    for who, text in out["crontabs"].items():
        out["jobs"] += parse_cron(text, source=f"crontab:{who}")
    return out


def trace_inputs(command, inputs=None):
    """Which attacker-influenceable paths does this consumer touch, and
    which dangerous ops does it use? Returns {inputs: [...], ops: [...]}."""
    inputs = inputs or ATTACKER_INPUTS
    found = [p for p in inputs if p in (command or "")]
    ops = [name for name, rx in DANGEROUS_OPS if re.search(rx, command or "")]
    return {"inputs": found, "ops": ops}


def path_canaries(name="payload"):
    """The path-contract test corpus: every way a name can be mangled into
    a path escape. Feed these as filenames/content to the consumer and
    watch which one it resolves."""
    return [
        name,
        f"./{name}",
        f"../{name}",
        f"{name}/../{name}",
        f"../../../../tmp/{name}",
        f"/tmp/{name}",
        f"/{name}",
        f"{name};id",
        f"{name}$(id)",
        f"{name}&&id",
        f"{name}|id",
        f"{name} {name}",
        f"{name}\\n",
        f"{name}/",
        f"-{name}",
        f"--{name}",
        f"*",
        f"*;id",
        f"{name}.*",
        f"{name}.txt",
        f"{name}.log",
        f"{name}.old",
        f"{name}~",
        f"{name}.bak",
        f"{name}.php",
        f"{name}.sh",
    ]


def audit(exec_one=None, inputs=None, canary_name="payload"):
    """Full dataflow audit: inventory + traces + ranked risk. Returns dict."""
    exec_one = exec_one or local_exec_one
    report = inventory_timers(exec_one)
    report["traces"] = []
    report["canaries"] = path_canaries(canary_name)
    for job in report["jobs"]:
        t = trace_inputs(job.get("command", ""), inputs)
        if t["inputs"] or t["ops"]:
            report["traces"].append({"job": job, **t})
    report["risks"] = sorted(report["traces"], key=lambda t: -len(t["ops"]))
    report["verdict"] = (
        f"{len(report['jobs'])} periodic consumer(s), "
        f"{len(report['traces'])} touching attacker inputs, "
        f"{len(report['risks'])} with dangerous ops")
    return report


def cli_priv(args):
    import json
    report = audit(local_exec_one, canary_name=args.canary)
    print(f"priv audit — {report['verdict']}")
    for t in report["risks"][:10]:
        job = t["job"]
        print(f"  !! {job['source']} [{job['user']}] {job['command'][:90]}")
        print(f"      inputs: {', '.join(t['inputs']) or '-'} · "
              f"ops: {', '.join(t['ops']) or '-'}")
    if args.json:
        print(json.dumps(report, indent=1, default=str))
    return 0


def build_arg_parser(sub):
    p = sub.add_parser("priv", help="privileged-consumer dataflow audit: "
                       "timers/cron inventory, input-source tracing, "
                       "path-escape canaries (lesson 22)")
    p.add_argument("--canary", default="payload",
                   help="canary name for path-contract tests")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cli_priv)
    return p
