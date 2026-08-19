#!/usr/bin/env python3
"""
payload.py — cross-boundary payload discipline + process-kill self-match guard.

Post-Cobblestone lessons 11-15, enforced in code:

* Every payload that crosses an exec boundary is built from INLINE LITERALS.
  Shell variables are never expanded across the boundary — the operator's
  value is quoted into the command once, on our side. `assert_literal`
  refuses anything with $VAR / ${...} / $(...) / `...` / $((...)).
* State-changing commands print nothing on success (remount is the classic:
  `mount -o remount,rw` succeeds silently). Every such command is followed
  by an explicit verify command whose output must contain a flag; the pair
  is echoed between BEGIN/END markers so truncated streams cannot fake a
  success.
* Side effects are never trusted before the namespace is proven:
  NSpid + userns inode tell us whether the pod shares the host PID/user
  namespace before we trust "pod-side" changes to mean "host-side" changes.
* pkill -f matches its own command line — the classic self-match kills the
  attacker's own shell. `safe_kill` auto-brackets the pattern; raw pkill -f
  is banned in rack scripts (enforced at atomic-test execution).
"""
import os
import re
import shlex
from functools import partial

HOST_USERNS_INODE = "4026531837"   # initial user namespace on Linux
HOST_PIDNS_INODE = "4026531836"    # initial PID namespace on Linux


class PayloadViolation(Exception):
    """A payload crossed the boundary with live shell expansion."""


# ---------------- literal payloads ----------------
def literal(*args):
    """Build a command from inline literals. Every word is quoted on OUR
    side — nothing survives to be expanded on the target."""
    return " ".join(shlex.quote(a) for a in args)


# expansions that would make the TARGET shell evaluate our text
_EXPANSION_RE = re.compile(r"\$\(|\$\{|\$\[|\$[A-Za-z_@*#?0-9!\-]|`")


def assert_literal(cmd):
    """Refuse any payload that carries live shell expansion across the
    boundary. Returns cmd unchanged; raises PayloadViolation with the
    offending fragments."""
    offenders = []
    for m in _EXPANSION_RE.finditer(cmd):
        start = max(0, m.start() - 12)
        offenders.append(cmd[start:m.start() + 24])
    if offenders:
        raise PayloadViolation(
            "live shell expansion in payload (inline literals only): "
            + " | ".join(offenders))
    return cmd


# ---------------- echo markers + verify flags ----------------
def marker_wrap(cmd, marker="SR", label="step"):
    """Echo BEGIN/END markers around a command and capture its exit code,
    so truncated or interleaved output can never fake a success."""
    return (f"echo '__{marker}_{label}_BEGIN__'; {cmd}; "
            f"rc=$?; echo \"__{marker}_{label}_END__ rc=$rc\"")


def verify_after(state_cmd, verify_cmd, expect):
    """A state-changing command that prints nothing on success MUST be
    paired with an explicit verify command whose output must contain the
    expected flag. Returns the pair as a dict — callers run both and check
    `expect` in the verify output before claiming the state change."""
    return {"cmd": state_cmd, "verify": verify_cmd, "expect": expect}


def remount_rw(mount_path):
    """`mount -o remount,rw` prints nothing on success — verify via
    /proc/mounts, the only oracle that cannot lie."""
    return verify_after(
        f"mount -o remount,rw {shlex.quote(mount_path)}",
        f"grep -F ' {shlex.quote(mount_path)} ' /proc/mounts",
        expect="rw")


def marker_value(output, marker="SR", label="step"):
    """Extract everything between the BEGIN/END markers of one wrapped
    command, so mixed/truncated stream output is handled deterministically."""
    m = re.search(re.escape(f"__{marker}_{label}_BEGIN__") + r"(.*?)"
                  + re.escape(f"__{marker}_{label}_END__"), output or "",
                  re.S)
    return m.group(1) if m else None


# ---------------- namespace proof (NSpid / userns) ----------------
def parse_nspid(status_text):
    """NSpid line of /proc/<pid>/status. The LAST number is the PID inside
    the innermost namespace; a list longer than 1 proves the process lives
    in nested PID namespaces (a pod). Pure function — unit-tested."""
    for line in (status_text or "").splitlines():
        if line.startswith("NSpid:"):
            return [int(x) for x in line.split()[1:]]
    return []


def ns_inode(path):
    try:
        link = os.readlink(path)
        return link.split("[")[-1].rstrip("]")
    except OSError:
        return None


def ns_check():
    """Prove the namespace before trusting side effects. Returns:
    host_pidns / host_userns / nspid / verdict — pod-side effects mean
    host-side effects ONLY when both namespaces are the host's."""
    status = ""
    try:
        with open("/proc/self/status", "r", encoding="utf-8") as f:
            status = f.read()
    except OSError:
        pass
    nspid = parse_nspid(status)
    userns = ns_inode("/proc/self/ns/user")
    pidns = ns_inode("/proc/self/ns/pid")
    host_userns = userns == HOST_USERNS_INODE
    host_pidns = pidns == HOST_PIDNS_INODE
    nested = len(nspid) > 1
    return {
        "nspid": nspid,
        "userns_inode": userns,
        "pidns_inode": pidns,
        "host_userns": host_userns,
        "host_pidns": host_pidns,
        "pod_side_effects_trustworthy": (not nested) and host_userns,
        "note": ("pod in nested pid namespace — verify every side effect with "
                 "flags, never trust visibility alone" if nested or not host_userns
                 else "host pid+user namespace — side effects are host-side"),
    }


# ---------------- pkill self-match guard ----------------
def bracket(pattern):
    """Bracket the first char so the pattern cannot match its own pkill
    command line. [f]oo matches foo but not `pkill -f [f]oo`."""
    if not pattern:
        raise ValueError("empty kill pattern")
    if len(pattern) == 1:
        return f"[{pattern}]"
    return f"[{pattern[0]}]{pattern[1:]}"


def safe_kill(pattern, sig=None):
    """pkill with the self-match guard already applied. Always use this —
    never raw pkill -f."""
    return ["pkill", "-f", bracket(pattern)] + ([f"-{sig}"] if sig else [])


_PKILL_RE = re.compile(r"\bpkill\s+-f\s+(\S+)")


def audit_pkill(cmd):
    """Find raw `pkill -f <pattern>` usages whose pattern is NOT bracketed.
    Returns a list of (pattern, reason). Empty list = clean."""
    violations = []
    for m in _PKILL_RE.finditer(cmd or ""):
        pat = m.group(1).strip("\"'")
        if not pat:
            violations.append(("", "empty pattern"))
        elif not re.match(r"^\[.\]", pat):
            violations.append((pat, "unbracketed — pkill -f self-match risk"))
    return violations


def _harden_repl(m, state):
    arg = m.group(1)
    quote = ""
    if arg[:1] in ("'", '"'):
        quote, arg = arg[0], arg[1:]
    end = ""
    if arg[-1:] in ("'", '"') and quote:
        end, arg = arg[-1], arg[:-1]
    # already bracketed, empty, or shell-expansion-derived: leave it —
    # expansion-derived patterns cannot be safely rewritten, the caller BANS
    if not arg or re.match(r"^\[.\]", arg) or "$" in arg or "`" in arg:
        return m.group(0)
    state["changed"] += 1
    return f"pkill -f {quote}{bracket(arg)}{end}"


def harden_pkill(cmd):
    """Auto-bracket every bracketable raw pkill -f pattern. Returns
    (new_cmd, n_changed). Expansion-derived patterns ($VAR, `cmd`) are left
    alone — the caller must BAN them."""
    state = {"changed": 0}
    new = _PKILL_RE.sub(partial(_harden_repl, state=state), cmd or "")
    return new, state["changed"]
