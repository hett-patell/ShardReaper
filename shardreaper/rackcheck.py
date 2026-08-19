#!/usr/bin/env python3
"""
rackcheck.py — the rack's own regression gate.

Post-Cobblestone lesson 15: "fixed" means TESTED before the next
engagement. Two structural checks run here and inside `healthcheck`:

1. AST structural check: no function definitions nested inside module
   functions ("methods inside functions"). Every nested def that looks
   harmless is where a previous pass stashed a helper the runner never
   re-discovers — the class of bug that cost real engagement hours.
   Class methods are fine; defs inside defs are not.
2. pkill self-match audit: raw `pkill -f <pattern>` without a bracketed
   first character is flagged across the rack (atomic test commands,
   rendered commands). Execution-time enforcement lives in atomics.run_test.

stdlib-only, deterministic, no network.
"""
import ast
import glob
import os
import re

from .payload import audit_pkill


def _walk_body(body, depth, chain, name, violations):
    for node in body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if depth > 0:
                violations.append(
                    f"{name}:{node.lineno} def {node.name}() nested inside "
                    f"module function {chain[0]} — hoist it to module level")
            _walk_body(list(node.body), depth + 1, chain + [node.name],
                       name, violations)
            # nested classes inside functions
            for child in node.body:
                if isinstance(child, ast.ClassDef):
                    violations.append(
                        f"{name}:{child.lineno} class {child.name} nested "
                        f"inside function {node.name} — hoist it")
        elif isinstance(node, ast.ClassDef):
            # methods on a class are legitimate — recurse only to catch
            # defs nested inside methods
            for meth in node.body:
                if isinstance(meth, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    _walk_body(list(meth.body), depth + 1, [meth.name],
                               name, violations)


def structural_check_src(src, name="<src>"):
    """AST check on source text. Returns a list of violation strings."""
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        return [f"{name}: syntax error: {e.msg} (line {e.lineno})"]
    violations = []
    _walk_body(list(tree.body), 0, [], name, violations)
    return violations


def structural_check(paths):
    """AST structural check over files. Returns a list of violations."""
    violations = []
    for path in paths:
        try:
            with open(path, encoding="utf-8") as f:
                src = f.read()
        except OSError as e:
            violations.append(f"{path}: unreadable: {e}")
            continue
        violations += structural_check_src(src, path)
    return violations


def package_py_files(package_dir):
    return sorted(glob.glob(os.path.join(package_dir, "*.py")))


def atomic_test_commands(atomic_root):
    """Collect command fields from the atomic rack (regex over YAML — no
    pyyaml dependency). Yields (path, command_fragment)."""
    if not atomic_root or not os.path.isdir(atomic_root):
        return
    for path in glob.glob(os.path.join(atomic_root, "atomics", "**", "*.yaml"),
                          recursive=True):
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                txt = f.read()
        except OSError:
            continue
        for m in re.finditer(r"command:\s*\n\s*([^\n]+)", txt):
            yield path, m.group(1)
        for m in re.finditer(r"command:\s*(\S[^\n]*)", txt):
            yield path, m.group(1)


def pkill_audit(atomic_root=None, extra_cmds=()):
    """Raw pkill -f scan over the atomic rack + extra command strings."""
    violations = []
    for path, cmd in atomic_test_commands(atomic_root):
        violations += [{"source": path, "pattern": p, "reason": r}
                       for p, r in audit_pkill(cmd)]
    for cmd in extra_cmds:
        violations += [{"source": "<cmd>", "pattern": p, "reason": r}
                       for p, r in audit_pkill(cmd)]
    return violations


def rack_check(package_dir=None, atomic_root=None):
    """Full rack regression check. Returns a report dict."""
    pkg = package_dir or os.path.join(os.path.dirname(os.path.abspath(__file__)))
    struct = structural_check(package_py_files(pkg))
    pkill = pkill_audit(atomic_root)
    return {"package": pkg,
            "structural_violations": struct,
            "pkill_violations": [{"source": v["source"], "pattern": v["pattern"]}
                                 for v in pkill],
            "structural_ok": not struct,
            "pkill_ok": not pkill}


def cli_rack_check(args):
    import json
    report = rack_check(package_dir=args.package, atomic_root=args.atomic)
    print(f"rack check @ {report['package']}")
    print(f"  structural (no defs nested in functions): "
          f"{'CLEAN' if report['structural_ok'] else f'{len(report['structural_violations'])} VIOLATION(S)'}")
    for v in report["structural_violations"]:
        print(f"    !! {v}")
    print(f"  raw pkill -f in rack scripts: "
          f"{'CLEAN' if report['pkill_ok'] else f'{len(report['pkill_violations'])} VIOLATION(S)'}")
    for v in report["pkill_violations"][:20]:
        print(f"    !! {v['source']}: {v['pattern']}")
    if args.json:
        print(json.dumps(report, indent=1))
    return 0 if (report["structural_ok"] and report["pkill_ok"]) else 1


def build_arg_parser(sub):
    p = sub.add_parser("rack-check", help="rack regression gate: AST structural "
                       "check (no methods nested in module functions) + raw "
                       "pkill -f audit")
    p.add_argument("--package", default=None, help="python package dir "
                   "(default: shardreaper/)")
    p.add_argument("--atomic", default=None, help="Atomic Red Team root for "
                   "the pkill audit")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cli_rack_check)
    return p
