#!/usr/bin/env python3
"""
sink.py — sink contract BEFORE exploit construction (lesson 18).

The old failure: a payload was built for an injection sink whose render path
(raw HTML string, never compiled) one source read would have disqualified.
No template/SSTI/deserialization payload is constructed before the cheapest
oracle answers:

1. SOURCE FIRST — when public source / rendered template / entrypoint is
   reachable, READ it and check the render path (compile/eval/execute vs
   plain string concat). Source evidence outranks every black-box guess.
2. MARKER SELF-TEST — otherwise send a self-test marker ({{7*7}}, ${7*7},
   magic strings) and look for the expected side effect (49) in the output.
3. A SinkContract record is required before the attack phase will spend a
   payload on that sink: status proven | disproven | unverified, with the
   oracle and evidence recorded.
"""
import re

# sink kind -> marker payloads and their expected side effects
SINK_MARKERS = {
    "ssti": [("{{7*7}}", "49"), ("${7*7}", "49"), ("#{7*7}", "49"),
             ("<%= 7*7 %>", "49"), ("{7*7}", "49")],
    "template": [("{{7*7}}", "49"), ("{% 7*7 %}", "49")],
    "xss": [("__SRX__<img src=x onerror=window.__SRX__=1>", "__SRX__")],
    "ssrf": [("http://127.0.0.1:1/__SRSSRF__", "__SRSSRF__")],
    "rce-echo": [("__SRRCE__$(echo __SRRCE__)__SRRCE__", "__SRRCE__")],
    "deser": [("__SRDES__rO0AB__SRDES__", "__SRDES__")],
}

# source files that can prove/disprove a sink without firing anything
SOURCE_HINTS = {
    "ssti": ["app.py", "main.py", "views.py", "routes.py", "server.js",
             "index.js", "templates/*.html", "templates/*.j2",
             "templates/*.tpl", "requirements.txt", "package.json",
             "Gemfile", "go.mod", "pom.xml"],
    "template": ["templates/*.html", "templates/*.j2", "templates/*.php",
                 "*.tpl", "*.ejs", "*.pug"],
    "deser": ["requirements.txt", "package.json", "pom.xml", "Gemfile",
              "*.java", "*.py"],
    "rce-echo": ["*.php", "*.py", "*.js", "*.rb", "*.sh"],
}

# render-path keywords that DISQUALIFY a sink when read from source
DISQUALIFY = ["innerHTML", "document.write", "textContent", "escape",
              "htmlspecialchars", "escaped", "sanitize", "raw string",
              "str(", "format("]

# render-path keywords that CONFIRM a compile/execute path
CONFIRM = ["render_template", "jinja", "twig", "evaluate", "eval(",
           "exec(", "compile", "unserialize", "pickle.loads",
           "yaml.load", "marshal.loads", "dangerouslySetInnerHTML",
           "v-html", "|safe", "noescape", "mark_safe"]


def marker_payloads(kind):
    return list(SINK_MARKERS.get(kind, [("{{7*7}}", "49")]))


def source_hints(kind):
    return list(SOURCE_HINTS.get(kind, ["app.py", "main.py", "index.js"]))


def evaluate_source(kind, source_text):
    """Does the source PROVE or DISPROVE the sink? Returns (status, reason,
    hits). DISQUALIFY beats CONFIRM: a render path that escapes beats an
    eval call elsewhere in the file."""
    text = source_text or ""
    dis = [k for k in DISQUALIFY if k in text]
    conf = [k for k in CONFIRM if k in text]
    if dis:
        return ("disproven",
                f"render path is not compiled/executed: {', '.join(sorted(set(dis)))}",
                {"disqualify": sorted(set(dis)), "confirm": sorted(set(conf))})
    if conf:
        return ("proven",
                f"source shows a live {kind} render path: {', '.join(sorted(set(conf)))}",
                {"disqualify": [], "confirm": sorted(set(conf))})
    return ("unverified", "no render-path evidence in source", {})


def evaluate_marker(kind, output):
    """Did a self-test marker come back with its side effect?"""
    for payload, expect in marker_payloads(kind):
        if expect and expect in (output or ""):
            return "proven", f"marker side effect observed: {expect}"
    return "disproven", "no marker side effect in output"


def new_contract(eng, kind, sink, oracle="unset", status="unverified",
                 evidence=None, reason=""):
    """Record a sink contract on the engagement. Returns the record."""
    rec = {"kind": kind, "sink": sink, "oracle": oracle, "status": status,
           "evidence": evidence or [], "reason": reason,
           "updated": eng.state.get("updated")}
    contracts = eng.state.setdefault("sink_contracts", [])
    for i, c in enumerate(contracts):
        if c.get("kind") == kind and c.get("sink") == sink:
            contracts[i] = rec
            eng.save()
            return rec
    contracts.append(rec)
    eng.save()
    return rec


def contract_for(eng, kind, sink=None):
    """The existing contract for a sink, if any."""
    for c in eng.state.get("sink_contracts", []):
        if c.get("kind") == kind and (sink is None or c.get("sink") == sink):
            return c
    return None


def exploit_allowed(eng, kind, sink=None):
    """The attack gate: a payload may be constructed for this sink ONLY
    when a contract exists and is proven. Anything else returns the reason
    the attack must first run an oracle."""
    c = contract_for(eng, kind, sink)
    if not c:
        return False, (f"no sink contract for {kind}/{sink} — run the "
                       f"cheapest oracle (source read or marker self-test) "
                       f"before building a payload")
    if c.get("status") != "proven":
        return False, f"sink contract {kind}/{sink} is {c.get('status')}: "
        f"{c.get('reason', 'no oracle answer yet')}"
    return True, c.get("reason", "contract proven")


def cli_sink(args):
    from .state import Engagement
    import os as _os
    base = _os.path.abspath(args.dir)
    if not _os.path.isfile(_os.path.join(base, "state.json")):
        print(f"no engagement at {base}")
        return 1
    eng = Engagement.load(base)
    kind = args.kind
    print(f"sink contract: {kind} @ {args.sink or '(any)'}")
    for payload, expect in marker_payloads(kind):
        print(f"  marker: {payload!r}  ->  expect {expect!r}")
    print("  source-first files: " + ", ".join(source_hints(kind)))
    if args.source and _os.path.isfile(args.source):
        status, reason, hits = evaluate_source(
            kind, open(args.source, encoding="utf-8", errors="ignore").read())
        print(f"  source read: {status.upper()} — {reason}")
        rec = new_contract(eng, kind, args.sink, oracle="source",
                           status=status, evidence=hits, reason=reason)
        print(f"  recorded: {rec['kind']} {rec['sink']} -> {rec['status']}")
        return 0 if status == "proven" else 2
    c = contract_for(eng, kind, args.sink)
    if c:
        print(f"  existing contract: {c['status'].upper()} ({c['oracle']}) "
              f"— {c['reason']}")
        return 0 if c["status"] == "proven" else 2
    print("  no contract recorded yet — prove it before payloading")
    return 2


def build_arg_parser(sub):
    p = sub.add_parser("sink", help="sink contract gate: prove the "
                       "render/exec path (source read or self-test marker) "
                       "BEFORE building any injection payload")
    p.add_argument("dir", help="engagement folder")
    p.add_argument("--kind", required=True,
                   choices=sorted(SINK_MARKERS), help="injection class")
    p.add_argument("--sink", default=None, help="sink identifier (endpoint, field)")
    p.add_argument("--source", default=None,
                   help="path to source/template to evaluate the render path")
    p.set_defaults(fn=cli_sink)
    return p
