#!/usr/bin/env python3
"""ShardReaper self-tests — run: python3 -m pytest tests/ -q  (or directly)"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# keep the memory ledger hermetic during tests
os.environ.setdefault("SHARDREAPER_MEMORY_DIR",
                      tempfile.mkdtemp(prefix="shardreaper-mem-test-"))
os.environ.setdefault("SHARDREAPER_SKIP_ENVCHECK", "1")  # no tool probes in tests

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




# ---------------- memory / resume ----------------
def test_memory_roundtrip():
    from shardreaper import memory
    memory.log_finding("eng-a", "tgt.local", {"id": "F001", "severity": "high",
                                              "class": "idor", "title": "T1",
                                              "technique": "T1005"})
    memory.log_negative("tgt.local", "T1059", "no exec")
    memory.log_note("tgt.local", "WAF resets sessions")
    memory.touch_session("tgt.local", "eng-a")
    text = memory.pickup("tgt.local")
    assert "T1" in text and "high" in text
    assert "T1059" in text and "WAF resets sessions" in text
    assert "eng-a" in text
    # finding capture fires automatically from state
    with tempfile.TemporaryDirectory() as d:
        eng = Engagement(d, "eng-b")
        eng.add_finding("auto captured", "medium", "xss", "T1059.007",
                        "tgt2.local", ["ev"], "d")
        assert "auto captured" in memory.pickup("tgt2.local")


def test_memory_gc():
    from shardreaper import memory
    assert "findings.jsonl" in memory.gc(rotate=True)


# ---------------- web3 token-scan ----------------
EVM_FIXTURE = """
contract RugToken {
    address owner;
    function mint(address to, uint256 amount) public { }   // hidden mint
    function setFee(uint256 f) external { fee = f; }       // uncapped fee
    function renounceOwnership() public onlyOwner { }      // fake renounce
    function rug() external { selfdestruct(payable(owner)); }
}
"""
SOLANA_FIXTURE = """
pub fn set_mint_authority(ctx: Context<SetMintAuthority>) -> Result<()> {
    msg!("authority not renounced");
    Ok(())
}
"""


def test_token_scan_evm():
    from shardreaper.tokens import scan_file
    import tempfile as tf
    with tf.TemporaryDirectory() as d:
        p = os.path.join(d, "RugToken.sol")
        open(p, "w").write(EVM_FIXTURE)
        hits = scan_file(p)
    ids = {h["id"] for h in hits}
    assert "hidden-mint" in ids and "fee-manipulation" in ids
    assert "fake-renounce" in ids and "selfdestruct" in ids
    assert all(h["severity"] for h in hits)


def test_token_scan_solana():
    from shardreaper.tokens import scan_file
    import tempfile as tf
    with tf.TemporaryDirectory() as d:
        p = os.path.join(d, "lib.rs")
        open(p, "w").write(SOLANA_FIXTURE)
        hits = scan_file(p, chain="solana")
    assert any(h["id"] == "mint-authority-not-renounced" for h in hits)


# ---------------- platform reports ----------------
def test_report_platforms():
    from shardreaper.report import render_h1, render_bugcrowd, render_intigriti
    with tempfile.TemporaryDirectory() as d:
        eng = Engagement(d, "t1")
        eng.add_finding("IDOR on orders", "critical", "idor", "T1005",
                        "api.tgt", ["1. GET /api/orders/1", "2. change id -> 200"],
                        "read any user's orders")
        h1 = render_h1(eng)
        assert "Weakness" in h1 and "Steps to Reproduce" in h1 and "Impact" in h1
        bc = render_bugcrowd(eng)
        assert "VRT" in bc and "broken_access_control" in bc
        it = render_intigriti(eng)
        assert "Business impact" in it


def test_report_skips_gated_killed():
    from shardreaper.report import render_h1
    with tempfile.TemporaryDirectory() as d:
        eng = Engagement(d, "t1")
        eng.add_finding("killed finding", "low", "xss", "T1059.007",
                        "t", [], "d")
        eng.state["findings"][0]["gate"] = {"passed": False, "decision": "kill"}
        assert "killed finding" not in render_h1(eng)


# ---------------- triage / chain / surface / intel / map ----------------
def test_triage_gate():
    from shardreaper.analysis import run_gate
    ok = run_gate({f"q{i}": True for i in range(1, 8)} | {"q6": False})
    assert ok["passed"] and ok["decision"] == "submit"
    dup = run_gate({f"q{i}": True for i in range(1, 8)} | {"q6": True})
    assert not dup["passed"] and dup["decision"] == "kill"


def test_triage_command_noninteractive():
    from shardreaper.analysis import triage
    with tempfile.TemporaryDirectory() as d:
        eng = Engagement(d, "t1")
        eng.add_finding("x", "high", "idor", "T1005", "t", ["e"], "d")
        out = triage(eng, interactive=False, assume_yes=True)
        assert out and out[0][1]["passed"]
        assert eng.state["findings"][0]["gate"]["decision"] == "submit"


def test_chain_resolve():
    from shardreaper.analysis import chain
    from shardreaper.knowledge import Knowledge
    with tempfile.TemporaryDirectory() as d:
        eng = Engagement(d, "t1")
        eng.add_finding("IDOR on orders", "critical", "idor", "T1005",
                        "api.tgt", ["ev"], "d")
        out = chain(eng, Knowledge(), finding_id="F001")
    assert "F001" in out
    assert "ato" in out or "mass-data" in out


def test_surface_ranking():
    from shardreaper.analysis import surface
    with tempfile.TemporaryDirectory() as d:
        eng = Engagement(d, "t1")
        eng.state["targets"] = [{"host": "h1", "ports": {22: None, 8080: None},
                                 "urls": [{"url": "http://h1:8080", "status": 200,
                                           "tech": []}],
                                 "intel": {}, "findings": [
                                     {"severity": "high", "type": "exposed-path",
                                      "path": "/.env", "detail": "leak"}]}]
        eng.state["findings"] = [{"id": "F001", "title": "dead", "severity": "low",
                                  "gate": {"passed": False}}]
        out = surface(eng)
    assert "P1" in out and "P2" in out and "KILL LIST" in out


def test_map_class():
    from shardreaper.analysis import map_class
    from shardreaper.knowledge import Knowledge
    from shardreaper.weapons import Weapons
    from shardreaper.atomics import AtomicIndex
    kb = Knowledge()
    roots = kb.roots
    atomics = AtomicIndex(roots["atomic"]) if "atomic" in roots else None
    weapons = Weapons(roots)
    out = map_class(kb, atomics, weapons, "kerberos golden ticket")
    assert "playbooks" in out and "weapons" in out


# ---------------- autopilot ----------------
def test_autopilot_cli():
    from shardreaper.engine import engage, cli_autopilot
    from types import SimpleNamespace
    with tempfile.TemporaryDirectory() as d:
        base = os.path.join(d, "eng")
        engage(base, "ap", ["http://localhost:8000"], ["localhost"], [], "obj")
        rc = cli_autopilot(SimpleNamespace(dir=base, phases="", mode="yolo",
                                           go=False, mock=True, yes=True))
        assert rc == 0
        eng = Engagement.load(base)
        assert eng.phase == "report"
        assert os.path.isfile(os.path.join(base, "REPORT.md"))




def test_osint_expansion_patched():
    """OSINT expansion with crt.sh patched (no network): scope-filtered + liveness."""
    from shardreaper import osint as osintmod
    from shardreaper.scope import Scope
    osintmod.shutil.which = lambda name: None   # no external tools in tests
    osintmod.crtsh = lambda apex, timeout=25: {
        "api.example.com", "dev.example.com", "admin.example.com",
        "evil.net.example.com", "*.www.example.com",
    }
    scope = Scope(["example.com"], ["admin.example.com"], name="osint-test")
    # liveness: only api + dev resolve
    live = osintmod.osint_expand(
        scope, ["example.com"],
        resolve=lambda h: h in ("api.example.com", "dev.example.com"),
        log=lambda *a, **k: None)
    assert "api.example.com" in live
    assert "dev.example.com" in live
    assert "admin.example.com" not in live   # out-of-scope rule wins
    assert "evil.net.example.com" not in live  # no DNS



# ---------------- ultimate pass: awesome catalog, scope.md, navigator, validate, classify, redact, hunt ----------------
def test_awesome_weapons_parse():
    from shardreaper.weapons import _parse_awesome
    roots = corpus_roots()
    if "awesome" not in roots:
        return
    entries = _parse_awesome(roots["awesome"])
    assert len(entries) > 250
    assert any(e["phase"] == "initial-access" for e in entries)
    assert any("uac" in e["name"].lower() for e in entries)


def test_weapons_install_blocks():
    from shardreaper.weapons import _parse_rtt
    roots = corpus_roots()
    if "redteam-tools" not in roots:
        return
    entries = _parse_rtt(roots["redteam-tools"])
    with_install = [e for e in entries if e.get("install")]
    assert with_install, "install blocks should be captured"


def test_scope_md_load():
    from shardreaper.scope import Scope
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "scope.md")
        open(p, "w").write(
            "# Scope — demo\n## In scope\n* example.com\n* 10.0.0.0/8\n"
            "## Out of scope\n* admin.example.com\n## Seeds\n* http://api.example.com\n")
        s = Scope.load_md(p)
    assert s.in_scope_host("api.example.com")
    assert not s.in_scope_host("admin.example.com")
    assert s.in_scope_host("10.1.2.3")
    assert s.seeds == ["http://api.example.com"]


def test_navigator_layer():
    from shardreaper.atomics import build_navigator_layer
    with tempfile.TemporaryDirectory() as d:
        eng = Engagement(d, "t1")
        eng.log_action("T1003.001", "h1", "lsass dump", outcome="executed")
        eng.state["plan"] = [{"technique": "T1595.003 Wordlist Scanning"}]
        layer = build_navigator_layer(eng)
    tids = [t["techniqueID"] for t in layer["techniques"]]
    assert "T1003.001" in tids and "T1595.003" in tids
    assert layer["domain"] == "enterprise-attack"


def test_validate_command():
    from shardreaper.analysis import validate, ALWAYS_REJECTED
    with tempfile.TemporaryDirectory() as d:
        eng = Engagement(d, "t1")
        eng.add_finding("self-XSS on profile", "low", "self-xss", "T1059.007",
                        "t", [], "d")
        results = validate(eng, assume_yes=True)
        assert results[0][1]["decision"] == "kill"     # always-rejected class
        eng.add_finding("IDOR real", "high", "idor", "T1005", "t", ["ev"], "d")
        results = validate(eng, finding_ids=["F002"], assume_yes=True)
        assert results[0][1]["passed"]


def test_classify():
    from shardreaper.analysis import classify
    from shardreaper.knowledge import Knowledge
    out = classify("https://api.example.com/graphql", Knowledge())
    assert "graphql" in out
    out2 = classify("https://x/vpn/portal", Knowledge())
    assert "vpn" in out2


def test_report_redact():
    from shardreaper.report import redact
    md = "session=abc123 cookie=secret email=op@corp.com Bearer eyJhbGciOiJIUzI1NiJ9.x.y"
    out = redact(md)
    assert "op@corp.com" not in out and "[EMAIL]" in out
    assert "abc123" not in out and "Bearer [REDACTED]" in out
    assert "eyJhbGciOiJIUzI1NiJ9" not in out


def test_hunt_scaffold():
    from shardreaper.engine import cli_hunt
    from types import SimpleNamespace
    with tempfile.TemporaryDirectory() as d:
        base = os.path.join(d, "hunt")
        rc = cli_hunt(SimpleNamespace(dir=base, name="t", seeds=["http://a.example"],
                                      in_scope=["example.com"], out_of_scope=[],
                                      objective="o", mode="red-team"))
        assert rc == 0
        assert os.path.isfile(os.path.join(base, "scope.md"))
        assert os.path.isdir(os.path.join(base, "findings"))
        assert os.path.isdir(os.path.join(base, "evidence"))
        assert os.path.isfile(os.path.join(base, "state.json"))



# ---------------- post-Cobblestone hardening ----------------
def _fake_oracle_probe(secret="hunter2"):
    import re as _re
    def probe(cond):
        m = _re.match(r"ASCII\(SUBSTRING\(\(SECRET\),(\d+),1\)\)>(\d+)", cond)
        if m:
            return ord(secret[int(m.group(1)) - 1]) > int(m.group(2))
        m = _re.match(r"LENGTH\(\(SECRET\)\)<=(\d+)", cond)
        if m:
            return len(secret) <= int(m.group(1))
        return cond == "1=1"
    return probe


def test_sqli_variants():
    from shardreaper.sqli import variants
    vs = variants("-1")
    assert "-1" in vs and -1 in vs
    vs2 = variants(0)
    assert 0 in vs2 and "0" in vs2


def test_sqli_oracle_validate_and_extract():
    from shardreaper.sqli import Oracle
    oracle = Oracle(_fake_oracle_probe())
    v = oracle.validate()
    assert v["ok"] and v["true_cond_evaluates"] and not v["false_cond_evaluates"]
    assert oracle.extract_string("SECRET") == "hunter2"
    # a broken oracle must be detected, not silently trusted
    broken = Oracle(lambda cond: True)
    assert not broken.validate()["ok"]


def test_sqli_file_read_encoded():
    from shardreaper.sqli import file_read_payload, decode_exfil
    p = file_read_payload("mysql", "/etc/passwd")
    assert "TO_BASE64" in p and "LOAD_FILE" in p
    p2 = file_read_payload("mysql", "/etc/passwd", encoding="hex")
    assert "HEX(LOAD_FILE" in p2
    assert "pg_read_file" in file_read_payload("postgres", "/etc/passwd")
    # decode roundtrip
    import base64
    blob = base64.b64encode(b"root:x:0:0:root:/root:/bin/bash").decode()
    raw, how = decode_exfil("<div>" + blob + "</div>")
    assert raw.startswith(b"root:x:") and how == "base64"


def test_fuzz():
    from shardreaper.fuzz import harvest_refs, fuzz_paths
    refs = harvest_refs('<script src="/static/app.js"></script>'
                        '<?php include "skins.php"; ?>'
                        '<a href="admin.php">x</a>')
    assert "static/app.js" in refs or "skins.php" in refs or "admin.php" in refs
    found = fuzz_paths(lambda c: "content" if c.endswith("skins.php") else None,
                       ["index.php", "skins.php", "admin.php"], "/var/www/html")
    assert len(found) == 1 and found[0]["path"].endswith("skins.php")


def test_crack_ground_truth():
    from shardreaper.crack import verify, identify
    vectors = [
        ("secret", "$1$deadbeef$ybdbWGoRB3GJ6nEVnhq7O0"),
        ("secret", "$5$saltsalt$0IyaXrmV7.sGNS6tirgqHLqX/G.FBvgkYA.lpPdS5sA"),
        ("secret", "$6$saltsalt$TVLlQcbpFVof5W3Yz4DTP6gRstiNuHwwTt6GLc1E5n0U0aDehy0S5knV8wiOQSpT0Y77vwPZN.Pq.H91p5hVO1"),
        ("password123", "$5$rounds=1000$someval$5eCN1JFu72ZTrJI42vMI46knJHTfjz8CyI0eJtn5Ir/"),
    ]
    for pw, h in vectors:
        assert verify(pw, h), f"failed {h[:12]}"
        assert not verify("wrong", h)
    assert identify(vectors[0][1]) == "md5crypt"
    assert identify(vectors[1][1]) == "sha256crypt"
    assert identify(vectors[2][1]) == "sha512crypt"


def test_crack_wordlist():
    from shardreaper.crack import crack
    with tempfile.TemporaryDirectory() as d:
        wl = os.path.join(d, "wl.txt")
        open(wl, "w").write("password\npassword123\nadmin\n")
        pw, rule = crack("$5$rounds=1000$someval$5eCN1JFu72ZTrJI42vMI46knJHTfjz8CyI0eJtn5Ir/",
                         wl, rules=("", "c"))
        assert pw == "password123"
        pw2, _ = crack("$1$deadbeef$ybdbWGoRB3GJ6nEVnhq7O0", wl)
        assert pw2 is None


def test_envcheck():
    from shardreaper.envcheck import probe_tool, writable_dirs, format_report, arsenal_report
    r = probe_tool("definitely-not-a-real-tool-xyz", ["--version"])
    assert r["status"] == "missing"
    assert arsenal_report()["fallbacks"]["pure-crack"].startswith("ok")
    assert "writable" in writable_dirs([("tmp", tempfile.mkdtemp())])["tmp"]
    assert "hashcat" in format_report(arsenal_report())


def test_canary_url():
    from shardreaper.canary import canary_url
    u = canary_url("10.0.0.5", 8888, "tok123")
    assert u == "http://10.0.0.5:8888/tok123"


def test_transport_healthcheck():
    from shardreaper.transport import healthcheck, format_health
    r = healthcheck()
    for key in ("vpn_processes", "tun_present", "gateway", "dns"):
        assert key in r
    assert "TRANSPORT SELF-CHECK" in format_health(r)


def test_adaptive_policy():
    from shardreaper.recon import adaptive_policy
    assert adaptive_policy(50, 100, 0)["ban"] is False
    p = adaptive_policy(30, 100, 1)
    assert p["pause"] > 0 and p["timeout"] > 3.0
    assert adaptive_policy(2, 100, 2)["ban"] is True
    # small scans never ban
    assert adaptive_policy(0, 10, 3)["ban"] is False


def test_memory_checkpoint():
    from shardreaper import memory
    memory.checkpoint("eng-ckpt", "attack",
                      [{"id": "F001", "severity": "high", "title": "x"}],
                      ["T1059"], ["deep-web-audit"])
    roll = memory._rollup("_engagement_eng-ckpt")
    assert roll["checkpoints"][-1]["phase"] == "attack"

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
