#!/usr/bin/env python3
"""ShardReaper self-tests — run: python3 -m pytest tests/ -q  (or directly)"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shardreaper.scope import Scope, OutOfScopeError
from shardreaper.state import Engagement
from shardreaper.knowledge import Knowledge, corpus_roots
from shardreaper.weapons import Weapons
from shardreaper.atomics import AtomicIndex, _mini_yaml
from shardreaper.llm import extract_json


# ---------------- scope ----------------
def test_scope_patterns():
    s = Scope(["example.com", "*.sub.example.com", "api.exact.io",
               "10.0.0.0/8", r"re:^lab[0-9]+\.example\.com$", "svc.example.com:8443"],
              out_of_scope=["admin.example.com", "10.0.0.5"])
    assert s.in_scope_host("example.com")
    assert s.in_scope_host("api.example.com")          # apex rule covers subdomains
    assert s.in_scope_host("x.sub.example.com")        # wildcard rule
    assert s.in_scope_host("api.exact.io")
    assert not s.in_scope_host("api.exact.io.evil.net")
    assert s.in_scope_host("10.0.0.7")
    assert s.in_scope_host("10.255.1.1")
    assert not s.in_scope_host("11.0.0.1")
    assert s.in_scope_host("lab42.example.com")        # regex rule
    assert s.in_scope_host("svc.example.com")          # host part of port rule
    # deny wins
    assert not s.in_scope_host("admin.example.com")
    assert not s.in_scope_host("10.0.0.5")
    # port binding: the bound rule restricts ITS OWN match; apex rule still allows
    assert s.in_scope("svc.example.com", port=8443)
    # default deny
    assert not s.in_scope_host("elsewhere.net")
    assert s.reject_reason("elsewhere.net")


def test_scope_wildcard_excludes_apex():
    s = Scope(["*.sub.example.com"])
    assert s.in_scope_host("x.sub.example.com")
    assert not s.in_scope_host("sub.example.com")      # wildcard excludes the apex


def test_scope_regex_alone():
    s = Scope([r"re:^lab[0-9]+\.example\.com$"])
    assert s.in_scope_host("lab42.example.com")
    assert not s.in_scope_host("lab.example.com")
    assert not s.in_scope_host("lab42.example.com.evil.net")


def test_scope_port_binding_alone():
    s = Scope(["svc.example.com:8443", "web.example.com:8000-9000"])
    assert s.in_scope("svc.example.com", port=8443)
    assert not s.in_scope("svc.example.com", port=80)
    assert s.in_scope("web.example.com", port=8500)
    assert not s.in_scope("web.example.com", port=7999)


def test_scope_path_binding():
    s = Scope(["example.com/api"])
    assert s.in_scope("example.com", port=443, path="/api")
    assert s.in_scope("example.com", port=443, path="/api/v1/users")
    assert not s.in_scope("example.com", port=443, path="/admin")
    assert not s.in_scope("example.com", port=443, path="/")     # base path denied
    # path rule is port-blind
    assert s.in_scope("example.com", port=8080, path="/api")


def test_scope_bare_ipv6():
    s = Scope(["2001:db8::1"])
    assert s.in_scope_host("2001:db8::1")
    assert not s.in_scope_host("2001:db8::2")
    s6 = Scope(["2001:db8::/32"])
    assert s6.in_scope_host("2001:db8::42")
    assert not s6.in_scope_host("2001:db9::1")


def test_scope_check_missing_file():
    from shardreaper.scope import check
    rc = check(["example.com"], scope_path="/nonexistent/scope.json")
    assert rc == 1


def test_scope_wildcard_excludes_apex():
    s = Scope(["*.sub.example.com"])
    assert s.in_scope_host("x.sub.example.com")
    assert not s.in_scope_host("sub.example.com")      # wildcard excludes the apex


def test_scope_enforce_raises():
    s = Scope(["10.0.0.0/24"], name="lab")
    s.enforce("10.0.0.9")
    try:
        s.enforce("192.168.1.1")
        raise AssertionError("should have raised")
    except OutOfScopeError:
        pass


# ---------------- state ----------------
def test_engagement_roundtrip():
    with tempfile.TemporaryDirectory() as d:
        eng = Engagement(d, "t1")
        eng.log("hello")
        f = eng.add_finding("x", "high", "info-leak", "T1005", "host", ["ev"], "detail")
        assert f["id"] == "F001"
        eng2 = Engagement.load(d)
        assert eng2.state["findings"][0]["id"] == "F001"
        assert len(eng2.state["actions"]) == 0
        eng2.add_target("h1", url="http://h1")
        eng3 = Engagement.load(d)
        assert eng3.state["targets"][0]["host"] == "h1"


# ---------------- knowledge ----------------
def test_knowledge_corpus_mounted():
    roots = corpus_roots()
    assert "hacktricks" in roots, "hacktricks corpus must be beside the project"
    k = Knowledge(roots)
    hits = k.search("golden ticket kerberos", limit=5)
    assert hits, "expected hits for kerberos golden ticket"
    assert any(h["corpus"] in ("hacktricks", "ired", "bughunter") for h in hits)


def test_knowledge_paths_are_real():
    k = Knowledge()
    hits = k.search("unquoted service path", limit=3)
    for h in hits:
        assert os.path.isfile(h["path"]), f"bad path {h['path']}"


# ---------------- weapons ----------------
def test_weapons_builtin():
    w = Weapons({})
    r = w.search("port scan")
    assert r and any("RustScan" == e["name"] or "nmap" == e["name"] for e in r)
    assert w.by_phase("recon")


def test_weapons_corpus_parse():
    roots = corpus_roots()
    w = Weapons(roots if roots else None, refresh=True)
    entries = w._load()
    assert len(entries) >= len(__import__("shardreaper.weapons", fromlist=["BUILTIN"]).BUILTIN)
    # corpus parse should add toolkit tables when present
    if "toolkit" in roots:
        names = {e["name"] for e in entries}
        assert "RustScan" in names


# ---------------- atomics ----------------
SAMPLE = """attack_technique: T1003
display_name: 'OS Credential Dumping'
atomic_tests:
- name: Dump LSASS
  auto_generated_guid: 1111
  description: |
    Dumps lsass memory
  supported_platforms:
  - windows
  executor:
    command: |
      mimikatz "#{exe_path}" sekurlsa::logonpasswords
    name: command_prompt
  input_arguments:
    exe_path:
      description: path
      type: path
      default: C:\\Tools\\mimikatz.exe
"""


def test_mini_yaml():
    d = _mini_yaml(SAMPLE)
    assert d["attack_technique"] == "T1003"
    assert d["display_name"] == "OS Credential Dumping"
    assert len(d["atomic_tests"]) == 1
    t = d["atomic_tests"][0]
    assert t["name"] == "Dump LSASS"
    assert "mimikatz" in t["executor"]["command"]
    assert t["input_arguments"]["exe_path"]["default"] == "C:\\Tools\\mimikatz.exe"


def test_mini_yaml_platforms():
    src = """attack_technique: T1010
display_name: 'Application Window Discovery'
atomic_tests:
- name: Test one
  description: x
  supported_platforms:
  - windows
  - macos
  executor:
    command: |
      whoami
    name: sh
  dependencies:
  - description: prereq
    prereq_command: exit 0
"""
    d = _mini_yaml(src)
    assert d["atomic_tests"][0]["supported_platforms"] == ["windows", "macos"]


def test_atomic_index_real():
    roots = corpus_roots()
    if "atomic" not in roots:
        return
    idx = AtomicIndex(roots["atomic"])
    n_tech, n_tests = idx.count()
    assert n_tech > 300
    assert n_tests > 1500
    tech = idx.get("T1003")
    assert tech and tech["display_name"]
    sel = idx.select(["credential", "dump"], platform="windows", limit=5)
    assert sel
    r = idx.run_test(tech["tests"][0], dry_run=True)
    assert r["dry_run"] and r["cmd"]


def test_atomic_strict_select():
    roots = corpus_roots()
    if "atomic" not in roots:
        return
    idx = AtomicIndex(roots["atomic"])
    loose = idx.select(["web"], platform=None, limit=10, strict=False)
    strict = idx.select(["web"], platform=None, limit=10, strict=True)
    assert strict
    # every strict hit must match the keyword in the test NAME or technique name
    for s in strict:
        hay = (s["name"] + " " + s["technique_name"]).lower()
        assert "web" in hay
    # strict mode may be smaller but never empty
    assert all(s["score"] >= 2 for s in strict)


def test_tactical_weapon_mapping():
    from shardreaper.engine import TACTICAL_WEAPON_PHASES
    from shardreaper.weapons import Weapons
    w = Weapons(corpus_roots(), refresh=False)
    assert TACTICAL_WEAPON_PHASES["escalate"] == "privilege-escalation"
    assert TACTICAL_WEAPON_PHASES["exfil"] == ["exfiltration", "c2"]
    for key, wps in TACTICAL_WEAPON_PHASES.items():
        wps = wps if isinstance(wps, list) else [wps]
        got = []
        for wp in wps:
            got += w.by_phase(wp, limit=8)
        assert got, f"tactical phase {key} must resolve to weapons"


def test_phase_validation():
    from shardreaper.engine import cli_run
    import tempfile, os
    from types import SimpleNamespace
    with tempfile.TemporaryDirectory() as d:
        base = os.path.join(d, "eng")
        engage_local(base)
        ok = cli_run(SimpleNamespace(dir=base, phases="recon,bogus", go=False,
                                     mock=True, wordlist=None, top_ports=100,
                                     no_paths=False))
        assert ok == 2


def engage_local(base):
    from shardreaper.engine import engage
    engage(base, "t", ["http://localhost:8000"], ["localhost"], [], "obj", mock=True)


def test_engage_seed_scope_warning(tmp_path=None):
    import io, contextlib
    from shardreaper.engine import engage
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            engage(os.path.join(d, "eng"), "warn-demo", ["http://evil.net"],
                   ["localhost"], [], "")
        out = buf.getvalue()
        assert "OUT of scope" in out


# ---------------- llm ----------------
def test_extract_json():
    assert extract_json('x ```json\n{"a": 1}\n``` y') == {"a": 1}
    assert extract_json('{"b": 2}') == {"b": 2}
    assert extract_json("no json") is None


# ---------------- engine mock pipeline ----------------
def test_engine_mock_pipeline():
    from shardreaper.engine import engage, Engine
    with tempfile.TemporaryDirectory() as d:
        base = os.path.join(d, "eng")
        engage(base, "mock-lab", ["http://localhost:8000"], ["localhost"],
               ["admin.localhost"], "prove local lab access", mock=True)
        eng = Engine(base, phases=["recon", "analyze", "plan", "attack", "report"], mock=True)
        eng.run()
        assert eng.eng.state["targets"]
        assert eng.eng.state["plan"]
        report = os.path.join(base, "REPORT.md")
        assert os.path.isfile(report)
        assert "ShardReaper Engagement Report" in open(report).read()


def test_engine_tactical_phases():
    from shardreaper.engine import engage, Engine
    with tempfile.TemporaryDirectory() as d:
        base = os.path.join(d, "eng")
        engage(base, "tactical-lab", ["http://localhost:8000"], ["localhost"],
               [], "obj", mock=True)
        eng = Engine(base, phases=["escalate", "persist", "move", "harvest",
                                   "evade", "exfil", "report"], mock=True)
        eng.run()
        notes = eng.eng.state["notes"]
        tactical = [n for n in notes if str(n.get("kind", "")).startswith("tactical-")]
        assert len(tactical) == 6
        for n in tactical:
            assert n.get("weapons"), f"{n['kind']} must record weapons"
        assert os.path.isfile(os.path.join(base, "REPORT.md"))


def test_report_renders_findings():
    from shardreaper.report import render_report
    with tempfile.TemporaryDirectory() as d:
        eng = Engagement(d, "t1")
        eng.add_finding("Exposed .env with secrets", "high", "info-leak",
                        "T1552", "target.local", ["GET /.env -> 200"],
                        "AWS keys visible", "credential theft", "remove file")
        eng.add_finding("Missing security headers", "low", "hardening",
                        "T1595", "target.local", [], "no CSP/HSTS")
        eng.log_action("T1552", "target.local", "GET /.env", outcome="executed")
        md = render_report(eng)
        assert "F001" in md and "HIGH" in md and "F002" in md and "LOW" in md
        assert "attack.mitre.org" in md


if __name__ == "__main__":
    import traceback
    failed = 0
    for name, fn in sorted(list(globals().items())):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except Exception:
                failed += 1
                print(f"FAIL {name}")
                traceback.print_exc()
    print(f"\n{len([n for n in globals() if n.startswith('test_')]) - failed}/{len([n for n in globals() if n.startswith('test_')])} passed")
    sys.exit(1 if failed else 0)
