#!/usr/bin/env python3
"""
cli.py — ShardReaper command center.

    shardreaper engage <dir> --seeds http://tgt --in-scope tgt.corp
    shardreaper status <dir>
    shardreaper run <dir> --phases recon,analyze,plan,attack,report [--go]
    shardreaper report <dir>
    shardreaper kb <query>                 # search the local offensive corpus
    shardreaper atomic list|select|run     # Atomic Red Team weapons rack
    shardreaper weapons <query> [--phase]  # tool catalog
    shardreaper scope <target> [--scope file | --in-scope ...]
    shardreaper recon --host <host>        # ad-hoc single-host sweep (mock scope)
    shardreaper ask "<task>"               # LLM brain (needs SHARDREAPER_LLM_*)
"""
import argparse
import json
import sys

BANNER = r"""
███████╗██╗  ██╗ █████╗ ██████╗ ██████╗
██╔════╝██║  ██║██╔══██╗██╔══██╗██╔══██╗
███████╗███████║███████║██████╔╝██║  ██║
╚════██║██╔══██║██╔══██║██╔══██╗██║  ██║
███████╗██║  ██║██║  ██║██║  ██║██████╔╝
██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗
██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║

   one shard · sharpest edge · total harvest
"""


def _kb_open(args):
    from .knowledge import Knowledge
    path = Knowledge().open_best(" ".join(args.query), args.corpus)
    print(path if path else "no hit")


def _recon_ad_hoc(args):
    from .scope import Scope
    from .recon import run_recon
    host = args.host
    s = Scope(args.in_scope or [host], [], seeds=[host], name="ad-hoc")
    targets = run_recon(s, [host], wordlist=args.wordlist,
                        top_ports=args.top_ports)
    print(json.dumps(targets, indent=1, default=str)[:4000])


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    ap = argparse.ArgumentParser(
        prog="shardreaper",
        description="ShardReaper — complete autonomous red team agent.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="scope is enforced in code, deny-by-default. engage first, attack second.")
    ap.add_argument("--version", action="version",
                    version=f"shardreaper {__import__('shardreaper').__version__}")
    sub = ap.add_subparsers(dest="cmd")

    from . import engine, knowledge, atomics, weapons, scope as scopemod
    from . import report as reportmod
    from . import llm as llmmod
    from . import memory as memorymod
    from . import osint as osintmod
    from . import tokens as tokensmod
    from . import analysis as analysismod
    from . import sqli as sqlimod
    from . import fuzz as fuzzmod
    from . import crack as crackmod
    from . import envcheck as envcheckmod
    from . import canary as canarymod
    from . import transport as transportmod
    from . import spray as spraymod
    from . import k8s as k8smod
    from . import rackcheck as rackcheckmod

    engine.build_arg_parser(sub)
    reportmod.build_arg_parser(sub)
    atomics.build_arg_parser(sub)
    weapons.build_arg_parser(sub)
    llmmod.build_arg_parser(sub)
    memorymod.build_arg_parser(sub)
    osintmod.build_arg_parser(sub)
    tokensmod.build_arg_parser(sub)
    analysismod.build_arg_parser(sub)
    sqlimod.build_arg_parser(sub)
    fuzzmod.build_arg_parser(sub)
    crackmod.build_arg_parser(sub)
    envcheckmod.build_arg_parser(sub)
    canarymod.build_arg_parser(sub)
    transportmod.build_arg_parser(sub)
    spraymod.build_arg_parser(sub)
    k8smod.build_arg_parser(sub)
    rackcheckmod.build_arg_parser(sub)

    kb = sub.add_parser("kb", help="search the local offensive corpus")
    kb.add_argument("query", nargs="+")
    kb.add_argument("--limit", type=int, default=8)
    kb.add_argument("--corpus")
    kb.set_defaults(fn=lambda a: knowledge.cli_search(" ".join(a.query), a.limit, a.corpus))

    ko = sub.add_parser("kb-open", help="print best-hit path for a query")
    ko.add_argument("query", nargs="+")
    ko.add_argument("--corpus")
    ko.set_defaults(fn=_kb_open)

    sc = sub.add_parser("scope", help="deterministic scope gate")
    sc.add_argument("targets", nargs="+")
    sc.add_argument("--scope")
    sc.add_argument("--in-scope", action="append", default=[])
    sc.add_argument("--out-of-scope", action="append", default=[])
    sc.set_defaults(fn=lambda a: scopemod.check(a.targets, a.scope, a.in_scope,
                                                a.out_of_scope))

    rc = sub.add_parser("recon", help="ad-hoc single-host recon sweep")
    rc.add_argument("--host", required=True)
    rc.add_argument("--in-scope", action="append", default=[])
    rc.add_argument("--wordlist")
    rc.add_argument("--top-ports", type=int, default=100)
    rc.set_defaults(fn=_recon_ad_hoc)

    cp = sub.add_parser("corpus", help="show available corpus summary")
    cp.set_defaults(fn=lambda a: print(knowledge.Knowledge().summary()))

    args = ap.parse_args(argv)
    if not args.cmd:
        print(BANNER)
        ap.print_help()
        return 0
    fn = getattr(args, "fn", None)
    if not fn:
        print(f"no handler for '{args.cmd}'")
        return 2
    try:
        return fn(args) or 0
    except KeyboardInterrupt:
        print("\naborted by operator")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
