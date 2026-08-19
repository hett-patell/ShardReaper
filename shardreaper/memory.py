#!/usr/bin/env python3
"""
memory.py — ShardReaper's cross-engagement ledger (the "model resume").

Findings are captured AUTOMATICALLY whenever the engine confirms one, plus
manual operator notes, per-target rollups for /pickup, and negative records
for techniques that did not pay off on a given stack — so a resumed run
never re-proves a known finding or re-tests a dead class.

Storage: <project>/data/memory/ (self-contained; override SHARDREAPER_MEMORY_DIR)
  findings.jsonl        one row per confirmed finding (cross-target)
  negatives.jsonl       (host, technique, class) tried -> not confirmed
  targets/<host>.json   per-target rollup: sessions, findings, tested, notes
  notes.jsonl           operator notes

stdlib-only. Never raises into the engine: capture failures are swallowed.
"""
import json
import os
import time
from datetime import datetime, timezone

SCHEMA_VERSION = 1
MAX_BYTES = 10 * 1024 * 1024   # rotate a JSONL past 10 MB
KEEP = 3                       # rotated backups kept: .1 (newest) .. .3


def _root():
    env = os.environ.get("SHARDREAPER_MEMORY_DIR")
    if env:
        return os.path.expanduser(env)
    # self-contained: the ledger lives with the agent
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "data", "memory")


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _append(path, record, max_bytes=MAX_BYTES, keep=KEEP):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        if os.path.isfile(path) and os.path.getsize(path) > max_bytes:
            for i in range(keep, 0, -1):
                src = f"{path}.{i - 1}" if i > 1 else path
                dst = f"{path}.{i}"
                if os.path.isfile(src):
                    os.replace(src, dst)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except OSError:
        pass


def log_finding(engagement, target, finding):
    """Automatic capture — called by state.add_finding."""
    _append(os.path.join(_root(), "findings.jsonl"), {
        "ts": _now(), "schema": SCHEMA_VERSION, "engagement": engagement,
        "target": target, "id": finding.get("id"), "severity": finding.get("severity"),
        "class": finding.get("class") or finding.get("type"),
        "title": finding.get("title"), "technique": finding.get("technique"),
    })
    roll = _rollup(target)
    roll.setdefault("findings", []).append({
        "ts": _now(), "engagement": engagement, "id": finding.get("id"),
        "severity": finding.get("severity"), "title": finding.get("title"),
    })
    _save_rollup(target, roll)


def log_negative(host, technique, detail):
    """A technique was tried and did NOT confirm — never waste the call again."""
    _append(os.path.join(_root(), "negatives.jsonl"), {
        "ts": _now(), "schema": SCHEMA_VERSION, "host": host,
        "technique": technique, "detail": (detail or "")[:160],
    })
    roll = _rollup(host)
    roll.setdefault("tested", []).append(
        {"ts": _now(), "technique": technique, "detail": (detail or "")[:160]})
    _save_rollup(host, roll)


def log_note(host, text, engagement=None):
    """Manual operator note (the /remember command)."""
    _append(os.path.join(_root(), "notes.jsonl"), {
        "ts": _now(), "host": host, "engagement": engagement, "text": text[:2000]})
    roll = _rollup(host)
    roll.setdefault("notes", []).append({"ts": _now(), "text": text[:2000]})
    _save_rollup(host, roll)


def touch_session(host, engagement):
    """Record that an engagement touched this target (for /pickup history)."""
    roll = _rollup(host)
    sessions = roll.setdefault("sessions", [])
    sessions.append({"ts": _now(), "engagement": engagement})
    roll["last_seen"] = _now()
    _save_rollup(host, roll)


def _rollup(host):
    path = os.path.join(_root(), "targets", f"{host}.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"host": host, "schema": SCHEMA_VERSION, "sessions": [],
                "findings": [], "tested": [], "notes": [], "last_seen": None}


def _save_rollup(host, roll):
    roll["last_seen"] = _now()
    path = os.path.join(_root(), "targets", f"{host}.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(roll, f, indent=1)
    except OSError:
        pass


def pickup(host):
    """The resume brief: where we left off on this target."""
    roll = _rollup(host)
    lines = [f"pickup [{host}]", f"  last seen: {roll.get('last_seen') or 'never'}"]
    sessions = roll.get("sessions", [])
    if sessions:
        lines.append(f"  sessions: {len(sessions)} "
                     f"({', '.join(sorted({s.get('engagement') for s in sessions if s.get('engagement')})[-3:])})")
    findings = roll.get("findings", [])
    lines.append(f"  confirmed findings: {len(findings)}")
    for f in findings[-6:]:
        lines.append(f"    [{f.get('severity', '?')[:4]:4s}] {f.get('title', '')[:70]}")
    tested = roll.get("tested", [])
    if tested:
        lines.append(f"  already tested: {len(tested)} technique(s) — "
                     f"{', '.join(sorted({t.get('technique', '?') for t in tested})[-8:])}")
    notes = roll.get("notes", [])
    for n in notes[-3:]:
        lines.append(f"  note: {n.get('text', '')[:90]}")
    return "\n".join(lines)


def gc(dir_path=None, rotate=False, purge_backups=False, max_mb=10):
    """memory-gc: report sizes, rotate oversized JSONLs, purge backups."""
    d = os.path.expanduser(dir_path) if dir_path else _root()
    if not os.path.isdir(d):
        return f"no ledger at {d}"
    cap = int(max_mb) * 1024 * 1024
    lines = [f"ledger {d}:"]
    for fn in ("findings.jsonl", "negatives.jsonl", "notes.jsonl"):
        p = os.path.join(d, fn)
        size = os.path.getsize(p) if os.path.isfile(p) else 0
        lines.append(f"  {fn:16s} {size / 1024:9.1f} KB{'  (oversized)' if size > cap else ''}")
        if rotate and size > cap:
            for i in range(KEEP, 0, -1):
                src = f"{p}.{i - 1}" if i > 1 else p
                dst = f"{p}.{i}"
                if os.path.isfile(src):
                    try:
                        os.replace(src, dst)
                    except OSError:
                        pass
            lines.append(f"    rotated -> fresh")
    if purge_backups:
        for fn in ("findings.jsonl", "negatives.jsonl", "notes.jsonl"):
            for i in range(1, KEEP + 1):
                p = os.path.join(d, f"{fn}.{i}")
                if os.path.isfile(p):
                    try:
                        os.remove(p)
                    except OSError:
                        pass
        lines.append("  backups purged")
    return "\n".join(lines)


# ---------------- CLI ----------------
def cli_pickup(args):
    print(pickup(args.host))
    return 0


def cli_remember(args):
    host = args.host
    if not host and args.dir:
        from .state import Engagement
        from urllib.parse import urlparse
        base = os.path.abspath(args.dir)
        if os.path.isfile(os.path.join(base, "state.json")):
            eng = Engagement.load(base)
            seed = (eng.state.get("seeds") or ["unknown"])[0]
            host = (urlparse(seed if "://" in seed else "//" + seed).hostname or seed)
    log_note(host or "operator", " ".join(args.note))
    print(f"noted @ {host or 'operator'}")
    return 0


def cli_memory_gc(args):
    print(gc(args.dir, args.rotate, args.purge_backups, args.max_mb))
    return 0


def build_arg_parser(sub):
    p = sub.add_parser("pickup", help="resume brief for a target (memory ledger)")
    p.add_argument("host")
    p.set_defaults(fn=cli_pickup)

    r = sub.add_parser("remember", help="note something about the engagement")
    r.add_argument("note", nargs="+")
    r.add_argument("--host", default=None)
    r.add_argument("--dir", default=None, help="engagement dir (takes host from seeds)")
    r.set_defaults(fn=cli_remember)

    g = sub.add_parser("memory-gc", help="inspect/rotate/purge the memory ledger")
    g.add_argument("--dir", default=None)
    g.add_argument("--rotate", action="store_true")
    g.add_argument("--purge-backups", action="store_true")
    g.add_argument("--max-mb", type=int, default=10)
    g.set_defaults(fn=cli_memory_gc)
    return p
