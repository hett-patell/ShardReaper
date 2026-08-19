#!/usr/bin/env python3
"""RedAgent self-tests — run: python3 -m pytest tests/ -q  (or directly)"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redagent.scope import Scope, OutOfScopeError
from redagent.state import Engagement
from redagent.knowledge import Knowledge, corpus_roots
from redagent.weapons import Weapons
from redagent.atomics import AtomicIndex, _mini_yaml
from redagent.llm import extract_json


# ---------------- scope ----------------
def test_scope_patterns():
    s = Scope(["example.com", "*.sub.example.com", "api.exact.io",
               "10.0.0.0/8", "re:^lab[0-9]+\\.example\\.com$", "svc.example.com:8443"],
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
    s = Scope(["re:^lab[0-9]+\\.example\\.com$"])
    assert s.in_scope_host("lab42.example.com")
    assert not s.in_scope_host("lab.example.com")
    assert not s.in_scope_host("lab42.example.com.evil.net")


def test_scope_port_binding_alone():
    s = Scope(["svc.example.com:8443", "web.example.com:8000-9000"])
    assert s.in_scope("svc.example.com", port=8443)
    assert not s.in_scope("svc.example.com", port=80)
    assert s.in_scope("web.example.com", port=8500)
    assert not s.in_scope("web.example.com", port=7999)


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
    assert len(entries) >= len(__import__("redagent.weapons", fromlist=["BUILTIN"]).BUILTIN)
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


# ---------------- llm ----------------
def test_extract_json():
    assert extract_json('x ```json\n{"a": 1}\n``` y') == {"a": 1}
    assert extract_json('{"b": 2}') == {"b": 2}
    assert extract_json("no json") is None


# ---------------- engine mock pipeline ----------------
def test_engine_mock_pipeline():
    from redagent.engine import engage, Engine
    with tempfile.TemporaryDirectory() as d:
        base = os.path.join(d, "eng")
        engage(base, "mock-lab", ["http://localhost:8000"], ["localhost"],
               ["admin.localhost"], "prove local lab access", mock=True)
        eng = Engine(base, phases=["recon", "analyze", "plan", "report"], mock=True)
        eng.run()
        assert eng.eng.state["targets"]
        assert eng.eng.state["plan"]
        report = os.path.join(base, "REPORT.md")
        assert os.path.isfile(report)
        assert "RedAgent Engagement Report" in open(report).read()


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
