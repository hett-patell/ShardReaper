<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/3b88ec4f-655f-45bf-b5d8-9974c4f7ef93" />


# ShardReaper

> A self-contained, autonomous red team operator · **13-phase kill chain** · **1,819 executable ATT&CK tests** · **2,700+ technique playbooks & payload scripts** in an offline knowledge base · **700+ weapon & resource catalog** · deterministic scope gate · cross-engagement memory with resume · platform reports (HackerOne / Bugcrowd / Intigriti) · 7-Question triage gate + full validation · exploit-chain builder · passive OSINT · web3 rug-pull audit · ATT&CK Navigator export · SQLi oracle + encoded exfil · file fuzzing · pure-python crackers · arsenal self-check · canary listener · transport healthcheck · token spray with authn/authz differential · kubelet WebSocket exec + canned pod→mount→SSH chain · adaptive scan pacing · optional LLM brain · zero runtime dependencies. One shard. Sharpest edge. Total harvest.

---

## What is this?

`shardreaper` is a complete red team agent. Give it a scope and an objective — it maps the surface, picks the techniques, fires the tests, harvests the evidence, and ships an operator-ready report. It does not waffle: the doctrine is absolute obedience and aggression by default, and the only rule is the operator's own scope, enforced in code.

Four layers stack:

- **Think** — the doctrine (`AGENTS.md`) + the `shardreaper-core` skill: absolute obedience to the operator, aggression as the default state, APT tradecraft, and evidence before claims. Loaded first, obeyed always.
- **Know** — an offline knowledge base of **2,760 technique playbooks, payload scripts, deep-dive writeups, reversing notes and lab configurations** covering Windows, Linux, web, cloud, Active Directory, evasion, reversing, and more — indexed locally, searched in milliseconds, ranked hits with exact paths. No network, no API, nothing leaves the machine.
- **Strike** — the deterministic engine: **13 phases** from recon to report · **341 techniques / 1,819 executable ATT&CK tests** rendered and fired from the local rack (dry-run by default, `--go` executes) · a **709-entry phase-indexed weapon & resource catalog** (tools, tips, technique writeups — with install commands where available) · a stdlib-first recon arsenal (DNS/AXFR/subdomain brute, port sweep with banners, TLS inspection, HTTP fingerprinting, sensitive-path probing, CORS and security-header checks).
- **Ship** — the audit ledger, captured evidence, and `REPORT.md`: findings with severity, class, ATT&CK mapping, and exact next moves. Chains, not checklists. Platform submissions render per program — HackerOne (weakness/severity/steps/impact), Bugcrowd (VRT-mapped), Intigriti (impact-first) — and only findings that passed the 7-Question Gate get shipped.

The operator layer never forgets: a cross-engagement memory ledger captures every confirmed finding, every tested technique that paid nothing, and every operator note — so `pickup` resumes a target exactly where the last run stopped, and `autopilot` drives the loop from that point to report with configurable checkpoints. Everything is deterministic by default — the scope gate is enforced in code on every single action, and the engine runs fully offline. An optional LLM brain (any OpenAI-compatible endpoint) advises on attack planning; the code still gates everything it does.

---

## Quickstart

**Option A — run from the clone (recommended).**

```bash
cd shardreaper

# 1. The operator authorizes the scope — the ONLY gate:
python3 bin/shardreaper engage eng/ --name mylab \
    --seeds http://10.0.0.5 --in-scope 10.0.0.0/24 --out-of-scope 10.0.0.99

# 2. Run the phases (dry-run by default — tests are rendered, not fired):
python3 bin/shardreaper run eng/ --phases recon,analyze,plan,attack,report

# 3. Execute when the operator says so, then ship the report:
python3 bin/shardreaper run eng/ --phases attack --go
python3 bin/shardreaper report eng/
```

**Option B — pip install.**

```bash
pip install .
shardreaper status eng/
```

**Option C — skills bundle for any SKILL.md-compatible agent.**

Mount `skills/` in the agent's skill path (Claude Code, Codex, OpenCode, ...).
`AGENTS.md` is the doctrine; the nine skills load per phase. The full
knowledge layer ports to any skill-aware harness.

**What each path gives you:**

| Path | Engine + CLI | Skills bundle | LLM brain |
|---|---|---|---|
| **A — clone** | ✅ everything | ✅ | optional (`SHARDREAPER_LLM_*`) |
| **B — pip** | ✅ everything | ➕ mount `skills/` | optional |
| **C — skills only** | ❌ | ✅ | n/a |

Then describe the objective in plain English and let it run:

```text
> Engage 10.0.0.0/24. Find the crown jewels and prove the full chain.

  ⟳ loading skills: shardreaper-recon, shardreaper-attack …
    → osint: +9 live in-scope subdomains · recon: 14 hosts · 63 ports · 2 exposed .env
    → plan: HIGH /.env disclosure @ 10.0.0.7  ← confirm-and-exploit
    → attack: T1083 File and Directory Discovery (dry-run)
    → triage: F001 gate PASS · chain: .env -> credentials -> lateral

  Next: autopilot to report, or pickup after lunch — the ledger remembers.
```

> The block above is an illustrative transcript.

---

## The operator layer

Beyond the kill chain, ShardReaper carries the full operator toolkit:

- **Memory + resume** — every confirmed finding is auto-captured to a cross-engagement ledger; `pickup <host>` resumes exactly where the last run stopped (sessions, findings, already-tested techniques, notes); `remember` adds operator context; `memory-gc` keeps the ledger lean.
- **Autopilot** — `shardreaper autopilot <dir> --mode paranoid|normal|yolo` drives the engagement from wherever it stopped to report, with operator checkpoints; non-TTY stdin skips prompts; the scope gate stays on in every mode.
- **Triage + validation** — the 7-Question Gate (`triage`) kills N/A findings before report time; `validate` adds the always-rejected class list and 4 pre-submission checks (demonstrable now, accepted impact, evidence hygiene, honest severity). Gate results are stored on the finding, shown in `surface`, and skipped by platform reports.
- **Chain builder** — `chain --finding F001` turns a standalone finding into an A→B→C impact chain (IDOR→ATO, SSRF→cloud metadata, exposed .git→secrets→RCE, ...) with the playbook path for each step.
- **Surface + intel + classify + map** — `surface` ranks the discovered attack surface (P1/P2/kill list), `intel` maps the tech stack to attack playbooks (plus keyless NVD CVE lookup with `--online`), `classify` reads a URL's signatures (GraphQL/OAuth/JWT/SharePoint/M365/VPN...) into the classes that apply, `map` routes any class to playbooks + atomics + weapons in one shot.
- **OSINT** — passive scope expansion (certificate transparency + subfinder/assetfinder when installed), scope-filtered and liveness-probed, runs automatically before the active sweep.
- **Hunt scaffold** — `hunt <dir>` creates the full engagement workspace: BugHunter-compatible `scope.md` + machine-readable `scope.json`, findings/evidence/recon/reports folders, and the engagement assertion (red-team / wapt modes).
- **Platform reports** — `report --platform h1|bugcrowd|intigriti` emits program-shaped submissions, `--redact` strips operator PII and session secrets from the output before it ships; the default client report stays the red-team deliverable.
- **Navigator export** — `atomic navigator <dir>` turns the engagement's planned + executed techniques into an ATT&CK Navigator layer for the blue-team debrief.
- **Web3 audit** — `token-scan` catches the rug vectors (hidden mint, honeypot, fee manipulation, fake renounce, proxies, reentrancy, Solana authorities); the `shardreaper-web3` skill covers economics and access control.
- **Burp integration** — set `SHARDREAPER_PROXY=http://127.0.0.1:8080` and every request flows through your intercepting proxy (CONNECT tunnel for HTTPS); a Burp MCP config template ships in `templates/`.

## Field lessons — hardened on HTB Cobblestone

ShardReaper failed its first real machine, took the writeup, and turned every
failure into code. The fifteen lessons are now LAW (see `AGENTS.md` §8):

| # | Lesson | Enforced by |
|---|---|---|
| 1 | Exfil encoded, never raw regex off HTML | `sqli --file-read` generates base64/hex payloads; `sqli --decode` decodes locally |
| 2 | Every read primitive is a directory fuzzer | `fuzz` — harvest refs from rendered pages, feed candidates through your working exfil one-liner |
| 3 | Canary every URL-accepting endpoint before writing it off | `canary` — tokenized listener, loud token hits, JSONL log |
| 4 | Check your own transport before ban theories | `healthcheck` — vpn processes, tunnel, gateway TCP, DNS verdict |
| 5 | Oracle self-test before any extraction | `sqli.Oracle.validate()` — known-true vs known-false, refuses broken oracles |
| 6 | Magic values in every type form | `sqli <value>` — str/int/hex/negative variants |
| 7 | Prove the arsenal works before the engagement | `arsenal` — runs at every `engage`; `crack` is the pure-python fallback ($1$/$5$/$6$ + raw, ground-truthed against system crypt) |
| 8 | Pace scans; back off on filtered ratios | adaptive pacing in `recon` — pause/backoff/stop on answer-ratio collapse |
| 9 | Bias to action | doctrine — a canary is cheaper than a spec debate |
| 10 | Checkpoint the ledger after every phase | automatic in `engine.run()` — full findings land in cross-engagement memory + engagement-local snapshots, even when a phase crashes; `report` merges, never clobbers |
| 11 | Spray every credential everywhere | `spray` — every password/SA-token/JWT × kubelet/apiserver/registry/SSH/docker with all protocol variants |
| 12 | Authn ≠ authz; 400 ≠ 403 ≠ 500 | `spray.classify_response` — 401 auto-retries all held creds; 403-with-subprotocol-mismatch is never RBAC |
| 13 | Exec contract: side-effect probe first, then source | `kube probe` — marker round-trip before entrypoints; /proc/mountinfo, cgroup, SA token over black-box guessing |
| 14 | Literal payloads; verify flags after silent state changes | `payload` — no cross-boundary shell expansion, BEGIN/END markers, /proc/mounts rw-flag verify, NSpid/userns proof |
| 15 | pkill must never kill the caller; fixed = tested | `safe_kill` brackets patterns, raw `pkill -f` banned at execution; `rack-check` AST check + live recon smoke test |

---

## How it works

A 13-phase kill chain — `engage → recon → analyze → plan → attack →
escalate → persist → move → harvest → spray → evade → exfil → report` — with
scope enforced in code at every boundary.

- **engage** — the operator authorizes the scope (the only gate), seeds, and objective.
- **recon / analyze / plan** — surface mapping, service hints, ranked attack items with techniques attached. Exposed sensitive files become HIGH findings with captured evidence immediately.
- **attack** — fires the selected ATT&CK tests. Dry-run by default; `--go` executes.
- **escalate / persist / move / harvest / spray / evade / exfil** — tactical phases that pull the right playbooks, atomics, and weapons for each chain step; `spray` auto-fires every harvested credential against every authenticated surface.
- **report** — `REPORT.md` with findings, evidence, and next moves. Merges with any existing report and never clobbers a narrative with the empty template. Every action lands in a JSONL audit ledger; a run is resumable and auditable.

Two ways to drive it: plain English through a skill-aware agent, or the CLI directly.

```text
shardreaper kb "golden ticket kerberos"       # ranked hits, exact paths
shardreaper atomic select --technique T1003   # pick a test
shardreaper atomic run --technique T1003 --index 0 --go
shardreaper weapons "port scan" --phase recon # pull the tool
shardreaper scope 10.0.0.9 --scope eng/scope.json
```

Scope patterns: `example.com` (apex + subdomains) · `*.example.com`
(subdomains only) · `api.example.com` (exact) · `10.0.0.0/8` (IPv4 CIDR) ·
`2001:db8::/32` (IPv6 CIDR) · `re:^lab[0-9]+\.example\.com$` (regex) ·
`host:8443` (port-bound) · `host/api` (path-bound) · **deny wins · default deny**.

---

## Authorization

ShardReaper is for assets you **own** or have **written authorization to
assess** — signed engagements, bug-bounty in-scope assets, CTF challenges,
your own infrastructure.

The scope gate is the mechanism: every action — DNS lookups, port probes,
HTTP requests, test execution — passes through `scope.py`, enforced in code,
never by model judgment. Anything outside the operator's scope is never
touched, even to "prove" a finding. The gate exists to keep you inside your
authorization; running against systems you do not own is both illegal and
exactly what the gate is designed to stop. See [`SECURITY.md`](SECURITY.md)
for the full posture.

---

## What's inside

**12 skills**, loaded by phase:

| Category | # | Skills |
|---|---|---|
| Doctrine | 1 | `shardreaper-core` |
| Kill-chain phases | 8 | `shardreaper-recon` · `-attack` · `-persist` · `-privesc` · `-credharvest` · `-lateral` · `-evasion` · `-exfil-c2` |
| Operator layer | 3 | `shardreaper-osint` · `shardreaper-report` · `shardreaper-web3` |

**35 slash commands**: `engage`, `hunt`, `scope`, `recon`, `kb`, `classify`,
`plan`, `attack`, `escalate`, `harvest`, `exfil`, `report`, `autopilot`,
`pickup`, `remember`, `memory-gc`, `triage`, `validate`, `chain`, `surface`,
`intel`, `map`, `osint`, `token-scan`, `web3-audit`, `status`, `sqli`, `fuzz`,
`crack`, `arsenal`, `canary`, `healthcheck`, `spray`, `kube`, `rack-check` —
one per operator move.

**The engine** — deterministic, resumable, auditable:

| Module | Role |
|---|---|
| `engine.py` | 13-phase orchestrator + autopilot |
| `scope.py` | deterministic scope gate (deny-wins, default-deny) |
| `knowledge.py` | offline corpus router — 2,760 docs, ranked search |
| `atomics.py` | 341 techniques / 1,819 executable ATT&CK tests + Navigator export |
| `weapons.py` | 709-entry phase-indexed weapon & resource catalog |
| `recon.py` | stdlib-first recon arsenal + proxy + external tool wrappers |
| `osint.py` | passive scope expansion (CT logs, subfinder, assetfinder) |
| `memory.py` | cross-engagement ledger — findings, negatives, rollups, resume |
| `analysis.py` | triage gate, chain builder, surface ranking, intel, map |
| `tokens.py` | web3 rug-pull audit |
| `persona.py` | the operator doctrine, injected everywhere |
| `llm.py` | optional OpenAI-compatible brain |
| `state.py` | engagement ledger + resumable state |
| `report.py` | client deliverable + H1/Bugcrowd/Intigriti submissions + merge |
| `k8s.py` | kubelet WebSocket exec (v4/v5 channel framing) + canned pod→mount→remount→SSH chain + exec-contract probe |
| `spray.py` | token spray + authn/authz differential classifier (400/401/403/404/500) |
| `payload.py` | literal payload discipline, markers + verify flags, NSpid/userns proof, `safe_kill` |
| `rackcheck.py` | rack regression gate: AST structural check + pkill audit |

---

## Documentation

| Doc | Contents |
|---|---|
| [`README.md`](README.md) | This file — overview, quickstart, how it works |
| [`AGENTS.md`](AGENTS.md) | The doctrine — identity and law |
| [`commands/`](commands/) | 28 slash commands |
| [`skills/`](skills/) | 12 phase skills in SKILL.md format |
| [`templates/`](templates/) | Engagement + report templates, Burp MCP config example |
| [`tests/`](tests/) | 69 self-tests, all green |
| [`SECURITY.md`](SECURITY.md) | Authorized-use posture |
| [`LICENSE`](LICENSE) | MIT |

---

## Why this exists

Most red-team agent setups are either too generic (one big "security" prompt)
or too fragmented (bookmarked writeups re-read every engagement). Neither
scales past the second target.

ShardReaper was forged to close four gaps:

1. **No obedience model** — general-purpose agents stall, hedge, and moralize mid-operation → the doctrine makes the operator's word final and immediate.
2. **No deterministic gate** — scope left to model judgment is a liability → the gate is code: deny-by-default, deny-wins, on every action.
3. **No offline knowledge** — techniques scattered across browsers and wikis → 1,200+ playbooks indexed locally, searched in milliseconds, with exact paths.
4. **No executable attack rack** — plans without teeth → 1,819 ATT&CK tests rendered and executed with one flag, plus a weapon catalog per phase.

The name is the doctrine: a shard is what remains when a blade breaks —
smaller than the weapon, sharper than the weapon, the most dangerous part of
it. The reaper harvests what remains after.

---

## Roadmap

- [x] 13-phase engine · deterministic scope gate · offline knowledge base
- [x] ATT&CK execution rack with dry-run/`--go` · weapon catalog
- [x] Optional OpenAI-compatible LLM brain (persona + ROE always injected)
- [x] Cross-engagement memory ledger · pickup/remember/autopilot
- [x] Platform reports (H1 / Bugcrowd / Intigriti) · triage gate + full validation
- [x] Exploit-chain builder · surface ranking · intel (corpus + keyless NVD) · classify · map
- [x] Passive OSINT expansion · Burp proxy routing
- [x] Web3 rug-pull audit (token-scan + audit skill)
- [x] Full reference integration — 2,760-doc knowledge base, 709-entry catalog with install blocks, payload scripts, reversing/lab notes
- [x] Hunt scaffold (scope.md + workspace) · ATT&CK Navigator export · report redaction
- [x] Field-lesson hardening (HTB Cobblestone): encoded exfil, file fuzzing, canary listener, transport healthcheck, SQLi oracle self-test, magic variants, arsenal self-check, pure-python crackers, adaptive scan pacing, per-phase ledger checkpoints
- [x] v1.2 strike extensions: token spray with authn/authz differential (401 auto-retry, 403-protocol-mismatch ≠ RBAC), kubelet WebSocket exec (v4/v5 channel framing) + canned pod→mount→remount→SSH chain, exec-contract probe (side-effect first, then source), literal payload discipline with verify flags + NSpid proof, `safe_kill` pkill guard, report merge, rack AST structural check + recon smoke test
- [ ] Built-in HTTP exploitation primitives (auth-bypass checks, verb tampering)
- [ ] C2 module (implant wrappers, DNS channel templates)
- [ ] AD attack-path planning with graph collection
- [ ] Report export to DOCX with embedded evidence
- [ ] `shardreaper plugin` — install the skills into agent harnesses in one command

---

## About

One shard. Sharpest edge. Total harvest. Operate inside the authorization
the operator gave you — and nothing else.

## License

[MIT](LICENSE). Intended for authorized security testing only.

---

> *"Give the operator the right shard and it stops being a tool. It becomes a campaign."*
