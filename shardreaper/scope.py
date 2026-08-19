#!/usr/bin/env python3
r"""
scope.py — deterministic scope enforcement for ShardReaper.

The agent may run unattended and is trained to be aggressive. Aggression is
aimed by the OPERATOR's own rules, enforced in CODE — never by model judgment.
This module is the gate every single action passes through:

  * Default deny  — anything not matching an in-scope rule is OUT.
  * Deny wins     — an out-of-scope match excludes even if in-scope matches.
  * Only hosts/URLs that pass here may be touched. Period.

Pattern forms (matched against the target's host):
    example.com        -> the apex AND any subdomain (example.com, api.example.com)
    *.example.com      -> any subdomain (NOT the bare apex)
    api.example.com    -> that exact host
    10.0.0.0/8         -> any IPv4/IPv6 address in the CIDR
    re:^staging[0-9]+\.example\.com$   -> explicit regex (prefix re:)
    host:443           -> additionally binds to a port or port range (host:1-65535)
    host:/api          -> additionally binds to a path prefix
"""
import ipaddress
import re
from urllib.parse import urlparse


def _host_of(target):
    t = target.strip()
    # bare IPv6 (with or without brackets): parse directly, not as host:port
    if t.count(":") > 1 and "://" not in t:
        try:
            ipaddress.IPv6Address(t.strip("[]"))
            return t.strip("[]").lower()
        except ValueError:
            pass
    if "://" not in t:
        t = "//" + t
    host = (urlparse(t).hostname or "").lower().rstrip(".")
    # strip IPv6 brackets
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host


def _port_of(target):
    t = target.strip()
    if "://" not in t:
        t = "//" + t
    try:
        return urlparse(t).port
    except ValueError:
        return None


def _path_of(target):
    t = target.strip()
    if "://" not in t:
        t = "//" + t
    return (urlparse(t).path or "").rstrip("/") or "/"


class _Rule:
    """One parsed scope pattern with optional port/path binding."""

    def __init__(self, pattern):
        self.raw = pattern
        self.port = None
        self.path = None
        body = pattern.strip().lower()
        self.regex = None
        self.cidr = None
        self.hostpat = body
        if body.startswith("re:"):
            try:
                self.regex = re.compile(body[3:])
            except re.error:
                self.regex = None
            return
        # CIDR (IPv4/IPv6): 10.0.0.0/8, 2001:db8::/32
        if re.match(r"^[0-9a-f:.]+/\d+$", body):
            try:
                self.cidr = ipaddress.ip_network(body, strict=False)
            except ValueError:
                self.cidr = None
            return
        # path binding: host/path (e.g. example.com/api)
        if "/" in body and not body.startswith("re:"):
            host, _, path = body.partition("/")
            self.hostpat = host
            self.path = "/" + path
            return
        # port binding: host:PORT or host:P1-P2 — but NOT bare IPv6 (2001:db8::1)
        m = re.match(r"^(.*?):(\d+)(?:-(\d+))?$", body)
        if m and body.count(":") == 1:
            self.hostpat = m.group(1)
            self.port = (int(m.group(2)), int(m.group(3)) if m.group(3) else int(m.group(2)))
        else:
            self.hostpat = body

    def matches_host(self, host):
        if self.regex is not None:
            return self.regex.search(host) is not None
        if self.cidr is not None:
            try:
                return ipaddress.ip_address(host) in self.cidr
            except ValueError:
                return False
        if self.hostpat.startswith("*."):
            return host.endswith("." + self.hostpat[2:])
        # bare domain: apex or any subdomain; or exact host
        return host == self.hostpat or host.endswith("." + self.hostpat)

    def matches(self, host, port=None, path=None):
        if not self.matches_host(host):
            return False
        if self.port is not None:
            if port is None:
                return False
            lo, hi = self.port
            if not (lo <= port <= hi):
                return False
        if self.path is not None:
            if path is None:
                return False
            if not (path == self.path or path.startswith(self.path.rstrip("/") + "/")):
                return False
        return True

    def __repr__(self):
        return f"<Rule {self.raw}>"


class Scope:
    def __init__(self, in_scope, out_of_scope=None, seeds=None, name="engagement"):
        self.in_rules = [_Rule(p) for p in (in_scope or []) if p and p.strip()]
        self.out_rules = [_Rule(p) for p in (out_of_scope or []) if p and p.strip()]
        self.seeds = seeds or []
        self.name = name

    @classmethod
    def load(cls, path):
        import json
        with open(path, "r", encoding="utf-8") as f:
            d = json.load(f)
        return cls(d.get("in_scope", []), d.get("out_of_scope", []),
                   d.get("seeds", []), d.get("name", "engagement"))

    @classmethod
    def load_md(cls, path):
        """Load a BugHunter-style markdown scope file:
            ## In scope            ## Out of scope          ## Seeds
            * example.com          * admin.example.com      * http://api.example.com
            * 10.0.0.0/8
        """
        in_scope, out_of_scope, seeds, name = [], [], [], None
        section = None
        with open(path, "r", encoding="utf-8") as f:
            for ln in f:
                s = ln.strip()
                m = re.match(r"^#+\s*(.+)$", s)
                if m:
                    head = m.group(1).strip().lower()
                    if "in scope" in head or head == "in":
                        section = "in"
                    elif "out of scope" in head or head == "out":
                        section = "out"
                    elif "seed" in head:
                        section = "seeds"
                    else:
                        section = None
                    if "scope" in head and name is None:
                        name = m.group(1).strip()
                    continue
                m = re.match(r"^[-*]\s+(.+)$", s)
                if m and section:
                    item = m.group(1).strip()
                    if section == "in":
                        in_scope.append(item)
                    elif section == "out":
                        out_of_scope.append(item)
                    elif section == "seeds":
                        seeds.append(item)
        return cls(in_scope, out_of_scope, seeds, name or "engagement")

    def in_scope_host(self, target):
        """Host-level check (port/path blind) — used for DNS/discovery gates."""
        host = _host_of(target)
        if not host:
            return False
        if any(r.matches_host(host) for r in self.out_rules):
            return False
        return any(r.matches_host(host) for r in self.in_rules)

    def in_scope(self, target, port=None, path=None):
        """Full check including optional port/path binding."""
        host = _host_of(target)
        if not host:
            return False
        port = port if port is not None else _port_of(target)
        path = path if path is not None else _path_of(target)
        if any(r.matches(host, port, path) for r in self.out_rules):
            return False
        return any(r.matches(host, port, path) for r in self.in_rules)

    def reject_reason(self, target, port=None, path=None):
        """None if in scope, else a reason string (for the audit trail)."""
        host = _host_of(target)
        if not host:
            return "could not parse host"
        if any(r.matches(host, port, path) for r in self.out_rules):
            return f"{host} matches an out-of-scope rule"
        if not any(r.matches(host, port, path) for r in self.in_rules):
            return f"{host} matches no in-scope rule (default deny)"
        return None

    def enforce(self, target, port=None, path=None):
        """Raise OutOfScopeError unless the target is in scope. THE gate."""
        reason = self.reject_reason(target, port, path)
        if reason:
            raise OutOfScopeError(target, reason)
        return True

    def describe(self):
        lines = [f"scope [{self.name}]",
                 f"  in : {[r.raw for r in self.in_rules]}",
                 f"  out: {[r.raw for r in self.out_rules]}",
                 f"  seeds: {self.seeds}"]
        return "\n".join(lines)


class OutOfScopeError(Exception):
    def __init__(self, target, reason):
        super().__init__(f"OUT-OF-SCOPE: {target} — {reason}")
        self.target = target
        self.reason = reason


def check(targets, scope_path=None, in_scope=None, out_of_scope=None):
    """CLI entry: deterministic gate. Exits non-zero on any out-of-scope hit."""
    if scope_path:
        try:
            s = (Scope.load_md(scope_path) if scope_path.endswith(".md")
                 else Scope.load(scope_path))
        except (OSError, ValueError) as e:
            print(f"error loading scope {scope_path}: {e}")
            return 1
    else:
        s = Scope(in_scope, out_of_scope, name="cli")
    ok = True
    for t in targets:
        reason = s.reject_reason(t)
        if reason:
            print(f"OUT-OF-SCOPE  {t}  [{reason}]")
            ok = False
        else:
            print(f"IN-SCOPE     {t}")
    return 0 if ok else 1


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="ShardReaper deterministic scope gate")
    ap.add_argument("targets", nargs="+")
    ap.add_argument("--scope", help="engagement scope JSON")
    ap.add_argument("--in-scope", action="append", default=[])
    ap.add_argument("--out-of-scope", action="append", default=[])
    args = ap.parse_args()
    raise SystemExit(check(args.targets, args.scope, args.in_scope, args.out_of_scope))
