#!/usr/bin/env python3
"""
tokens.py — web3 token-scan: static rug-pull / scam-vector audit.

Checks token contracts for the classic rug vectors — hidden mint, honeypot
sell blocks, fee manipulation, fake renounce, authority retention, upgradeable
proxies, reentrancy, unlimited allowances, and the Solana equivalents. Pure
grep-pattern audit (EVM/Solidity + Solana/Rust), stdlib-only; an optional
external scanner (slither) is used when installed. Every hit is reported with
the offending line and a severity.
"""
import os
import re
import shutil
import subprocess

# (id, severity, [regexes], verdict)
EVM_PATTERNS = [
    ("hidden-mint", "critical",
     [r"function\s+mint\s*\([^)]*\)\s*(public|external)", r"\.mint\([^)]*\)",
      r"_mint\s*\([^)]*\)"],
     "mint capability that may remain callable or re-armed after launch"),
    ("fake-renounce", "critical",
     [r"renounceOwnership\s*\(\s*\)\s*[a-zA-Z_]*\s*\{", r"function\s+renounce",
      r"onlyOwner\s+renounce"],
     "renounce may be overridden, gated, or never actually executed"),
    ("honeypot-sell-block", "critical",
     [r"isContract\s*\([^)]*\)", r"blacklist\s*\[[^]]*\]",
      r"require\s*\(\s*!isContract", r"onlyAllowed"],
     "sell/transfer may be blocked for buyers (honeypot mechanics)"),
    ("fee-manipulation", "high",
     [r"function\s+setFee\s*\([^)]*\)", r"fee\s*=\s*[0-9]{2,}",
      r"tax\s*=\s*[0-9]{2,}", r"maxFee\s*="],
     "fees may be raised arbitrarily or start above 25%"),
    ("upgradeable-proxy", "high",
     [r"delegatecall\s*\([^)]*\)", r"proxyAdmin", r"function\s+upgrade",
      r"transparentProxy"],
     "logic can be swapped post-launch (proxy pattern)"),
    ("authority-retention", "high",
     [r"tx\.origin", r"setAuthority\s*\([^)]*\)", r"mintAuthority",
      r"freezeAuthority", r"onlyOwner[^;]*transfer"],
     "owner/authority may retain mint, freeze, or transfer powers"),
    ("unlimited-allowance", "medium",
     [r"approve\s*\([^,]+,\s*(type\(uint256\)\.max|2\s*\*\*\s*256\s*-\s*1|uint256\(-1\))"],
     "unlimited token allowance granted"),
    ("reentrancy", "high",
     [r"call\.value[^;]*;", r"\.call\s*\{\s*value:\s*[^}]*\}\s*\(",
      r"address\([^)]*\)\.call"],
     "external call with value — reentrancy risk without a guard"),
    ("selfdestruct", "high",
     [r"selfdestruct\s*\(", r"suicide\s*\("],
     "contract can destroy itself and sweep funds"),
    ("rug-signal", "medium",
     [r"function\s+rug\s*\(", r"function\s+rugPull\s*\(", r"drain\s*\(\s*\)"],
     "explicit rug/drain function present"),
]

SOLANA_PATTERNS = [
    ("mint-authority-not-renounced", "critical",
     [r"set_mint_authority", r"mint_authority", r"SetAuthority"],
     "mint authority may be retained (unlimited minting)"),
    ("freeze-authority", "critical",
     [r"freeze_authority", r"FreezeAccount"],
     "freeze authority may block sells"),
    ("transfer-hook", "high",
     [r"transfer_hook", r"TransferHook"],
     "transfer hook can conditionally block or tax transfers"),
    ("fee-manipulation", "high",
     [r"fee_basis_points\s*>\s*", r"fee\s*:\s*[0-9]{3,}"],
     "fees above 1000 bps (10%) or unbounded"),
    ("proxy-upgrade", "high",
     [r"programdata\s*::", r"upgradeable", r"solana_program::bpf_loader"],
     "program may be upgradeable post-launch"),
    ("authority-retention", "high",
     [r"authority\s*:\s*[^,}]*wallet", r"owner\s*:\s*[^,}]*wallet",
      r"withdraw\s*\([^)]*authority"],
     "withdraw/authority powers retained by a single key"),
]

ALLOWED_EXTS = (".sol", ".rs", ".vy", ".move", ".tact")


def scan_file(path, chain=None):
    try:
        text = open(path, "r", encoding="utf-8", errors="ignore").read()
    except OSError:
        return []
    hits = []
    lines = text.splitlines()
    use_solana = chain == "solana" or (chain is None and path.endswith(".rs"))
    patterns = SOLANA_PATTERNS if use_solana else EVM_PATTERNS
    for pid, sev, regexes, verdict in patterns:
        for i, ln in enumerate(lines):
            for rx in regexes:
                if re.search(rx, ln):
                    hits.append({"id": pid, "severity": sev, "line": i + 1,
                                 "code": ln.strip()[:120], "verdict": verdict,
                                 "file": path})
                    break
    return hits


def scan(paths, recursive=True, chain=None, log=None):
    log = log or (lambda *a, **k: None)
    files = []
    for p in paths:
        if os.path.isfile(p):
            files.append(p)
        elif os.path.isdir(p):
            for dirpath, _dirs, fns in os.walk(p):
                for fn in fns:
                    if fn.endswith(ALLOWED_EXTS):
                        files.append(os.path.join(dirpath, fn))
                if not recursive:
                    break
    hits = []
    for f in files:
        h = scan_file(f, chain)
        if h:
            hits += h
            log(f"token-scan: {f} -> {len(h)} hit(s)")
    # optional real scanner when installed
    for tool in ("slither", "aderyn"):
        if shutil.which(tool) and files:
            try:
                p = subprocess.run([tool, "--json", files[0]],
                                   capture_output=True, text=True, timeout=300)
                log(f"token-scan: {tool} -> rc={p.returncode} "
                    f"({len((p.stdout or '').splitlines())} lines)")
            except Exception:
                pass
    hits.sort(key=lambda h: (-{"critical": 3, "high": 2, "medium": 1, "low": 0}[h["severity"]],
                              h["file"], h["line"]))
    return hits


def cli_token_scan(args):
    hits = scan([args.path], recursive=args.recursive, chain=args.chain,
                log=lambda m: print(f"[token-scan] {m}"))
    if not hits:
        print("clean — no rug vectors matched")
        return 0
    print(f"{len(hits)} hit(s):")
    for h in hits:
        print(f"  [{h['severity'].upper():8s}] {h['id']:32s} {h['file']}:{h['line']}")
        print(f"           {h['code']}")
        print(f"           -> {h['verdict']}")
    if args.output:
        import json
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(hits, f, indent=1)
        print(f"report written: {args.output}")
    return 0


def build_arg_parser(sub):
    p = sub.add_parser("token-scan", help="rug-pull / scam-vector audit for token contracts")
    p.add_argument("path", help="contract file or directory")
    p.add_argument("--recursive", action="store_true", help="walk directories")
    p.add_argument("--chain", default="evm", choices=["evm", "solana"])
    p.add_argument("--output", default=None, help="write JSON report")
    p.set_defaults(fn=cli_token_scan)
    return p
