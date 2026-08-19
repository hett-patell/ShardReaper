#!/usr/bin/env python3
"""
weapons.py — the tool/weapons catalog.

Two sources, both offline:
  1. Builtin curated rack (always present) — the classics per phase.
  2. Parsed catalogs from the local reference repos (Red-Teaming-Toolkit's
     markdown tables and RedTeam-Tools' README), cached under data/cache/.

Every entry: name, phase(s), url, description. Phase names follow the
ATT&CK-ish taxonomy used across ShardReaper (recon, initial-access, execution,
persistence, privilege-escalation, defense-evasion, credential-access,
discovery, lateral-movement, collection, exfiltration, c2, misc).
"""
import json
import os
import re
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE_DIR = os.path.join(PROJECT_ROOT, "data", "cache")
CACHE_FILE = os.path.join(CACHE_DIR, "weapons.json")

BUILTIN = [
    # recon / discovery
    ("RustScan", "recon", "https://github.com/RustScan/RustScan", "Modern port scanner; full port scans in seconds."),
    ("nmap", "recon", "https://nmap.org", "The standard network mapper: port/service/OS detection, NSE scripts."),
    ("masscan", "recon", "https://github.com/robertdavidgraham/masscan", "Asynchronous port scanner, 25M ports/s."),
    ("Amass", "recon", "https://github.com/OWASP/Amass", "In-depth attack surface mapping and asset discovery."),
    ("BBOT", "recon", "https://github.com/blacklanternsecurity/bbot", "Recursive internet scanner; subdomains, assets, ports."),
    ("subfinder", "recon", "https://github.com/projectdiscovery/subfinder", "Passive subdomain enumeration."),
    ("dnsrecon", "recon", "https://www.kali.org/tools/dnsrecon/", "DNS enumeration: zone transfers, brute force, SRV, cache snooping."),
    ("dnscan", "recon", "https://github.com/rbsec/dnscan", "Wordlist-based DNS subdomain scanner."),
    ("SpiderFoot", "recon", "https://github.com/smicallef/spiderfoot", "OSINT automation over many data sources."),
    ("Recon-ng", "recon", "https://github.com/lanmaster53/recon-ng", "Web reconnaissance framework."),
    ("AttackSurfaceMapper", "recon", "https://github.com/superhedgy/AttackSurfaceMapper", "Automated attack surface reconnaissance."),
    ("shodan", "recon", "https://www.shodan.io", "Internet-wide asset/port/service intelligence."),
    ("cloud_enum", "recon", "https://github.com/initstring/cloud_enum", "Multi-cloud public resource enumeration (AWS/Azure/GCP)."),
    ("S3Scanner", "recon", "https://github.com/sa7mon/S3Scanner", "Find open S3 buckets and dump contents."),
    ("gitleaks", "recon", "https://github.com/zricethezav/gitleaks", "Secret detection in git repos."),
    ("truffleHog", "recon", "https://github.com/dxa4481/truffleHog", "Search git history for secrets."),
    ("gobuster", "recon", "https://www.kali.org/tools/gobuster/", "Directory/file/DNS/vhost brute forcing."),
    ("feroxbuster", "recon", "https://github.com/epi052/feroxbuster", "Fast recursive content brute force."),
    ("ffuf", "recon", "https://github.com/ffuf/ffuf", "Fast web fuzzer: dirs, params, vhosts."),
    ("nikto", "recon", "https://github.com/sullo/nikto", "Web server scanner: misconfigs, CVEs, dangerous files."),
    ("nuclei", "recon", "https://github.com/projectdiscovery/nuclei", "Template-based vulnerability scanner with 10k+ templates."),
    ("WitnessMe", "recon", "https://github.com/byt3bl33d3r/WitnessMe", "Web inventory with screenshots (headless Chrome)."),
    ("pagodo", "recon", "https://github.com/opsdisk/pagodo", "Automated Google dorking from GHDB."),
    ("spoofcheck", "recon", "https://github.com/BishopFox/spoofcheck", "SPF/DMARC weak-config check (domain spoofing)."),
    ("enum4linux", "discovery", "https://github.com/CiscoCXSecurity/enum4linux", "SMB/Windows enumeration via rpcclient."),
    ("BloodHound", "discovery", "https://github.com/BloodHoundAD/BloodHound", "AD attack-path mapping (with SharpHound collector)."),
    ("Seatbelt", "discovery", "https://github.com/GhostPack/Seatbelt", "Windows host situational-awareness enumerator."),
    ("LinPEAS", "privilege-escalation", "https://github.com/peass-ng/PEASS-ng", "Linux privilege-escalation enumeration."),
    ("WinPEAS", "privilege-escalation", "https://github.com/peass-ng/PEASS-ng", "Windows privilege-escalation enumeration."),
    ("PowerUp", "privilege-escalation", "https://github.com/PowerShellMafia/PowerSploit", "Windows privesc checks (service misconfigs, tokens)."),
    ("sqlmap", "initial-access", "https://github.com/sqlmapproject/sqlmap", "Automated SQL injection and database takeover."),
    ("hydra", "initial-access", "https://github.com/vanhauser-thc/thc-hydra", "Fast network logon brute for 50+ protocols."),
    ("kerbrute", "initial-access", "https://github.com/ropnop/kerbrute", "Kerberos user enumeration and password spraying."),
    ("responder", "credential-access", "https://github.com/lgandx/Responder", "LLMNR/NBT-NS/mDNS poisoning for credential capture."),
    ("mimikatz", "credential-access", "https://github.com/gentilkiwi/mimikatz", "Windows credential extraction (lsass, tickets, hashes)."),
    ("Rubeus", "credential-access", "https://github.com/GhostPack/Rubeus", "Kerberos abuse: tickets, kerberoasting, asreproasting."),
    ("LaZagne", "credential-access", "https://github.com/AlessandroZ/LaZagne", "Dump stored credentials from 30+ Windows apps."),
    ("impacket", "lateral-movement", "https://github.com/fortra/impacket", "Network protocols in Python: psexec, wmiexec, secretsdump, ntlmrelayx."),
    ("evil-winrm", "lateral-movement", "https://github.com/Hackplayers/evil-winrm", "WinRM shell for pentesting."),
    ("CrackMapExec", "lateral-movement", "https://github.com/Pennyw0rth/NetExec", "Swiss-army AD testing: SMB/WinRM/exec/hash spray."),
    ("chisel", "c2", "https://github.com/jpillora/chisel", "Fast TCP/UDP tunnel over HTTP(S)."),
    ("ligolo-ng", "c2", "https://github.com/nicocha30/ligolo-ng", "Tunnel-based reverse proxy for pivoting."),
    ("dnscat2", "c2", "https://github.com/iagox86/dnscat2", "C2 over DNS."),
    ("Sliver", "c2", "https://github.com/BishopFox/sliver", "Cross-platform adversary emulation framework (implants, C2)."),
    ("Mythic", "c2", "https://github.com/its-a-feature/Mythic", "Multi-agent C2 framework with payload generators."),
    ("Empire", "c2", "https://github.com/BC-SECURITY/Empire", "PowerShell/Python post-exploitation agent framework."),
    ("metasploit", "initial-access", "https://www.metasploit.com", "Exploit development/execution framework (msfconsole, msfvenom)."),
    ("veil", "defense-evasion", "https://github.com/Veil-Framework/Veil", "AV-evading payload generation."),
    ("donut", "defense-evasion", "https://github.com/TheWover/donut", "Shellcode generation from PE/EXE/DLL in-memory."),
    ("macro_pack", "initial-access", "https://github.com/sevagas/macro_pack", "Obfuscated Office macros for initial access."),
    ("hashcat", "credential-access", "https://hashcat.net/hashcat/", "GPU password cracking."),
    ("john", "credential-access", "https://www.openwall.com/john/", "John the Ripper password cracker."),
    ("exfiltrator", "exfiltration", "https://github.com/madchat/exfiltrator", "Data exfiltration toolkit."),
    ("DNSExfiltrator", "exfiltration", "https://github.com/Arno0x/DNSExfiltrator", "Exfiltrate data over DNS."),
]

_RTK_SECTIONS = ["Reconnaissance", "Initial Access", "Delivery", "Situational Awareness",
                 "Credential Dumping", "Privilege Escalation", "Defense Evasion",
                 "Persistence", "Lateral Movement", "Exfiltration", "Miscellaneous"]

_PHASE_NORM = {
    "reconnaissance": "recon",
    "recon": "recon",
    "initial access": "initial-access",
    "delivery": "initial-access",
    "execution": "initial-access",
    "situational awareness": "discovery",
    "discovery": "discovery",
    "credential dumping": "credential-access",
    "credential access": "credential-access",
    "privilege escalation": "privilege-escalation",
    "escalation": "privilege-escalation",
    "defense evasion": "defense-evasion",
    "persistence": "persistence",
    "lateral movement": "lateral-movement",
    "collection": "collection",
    "exfiltration": "exfiltration",
    "miscellaneous": "misc",
    "misc": "misc",
    "c2": "c2",
    "command and control": "c2",
    "resource development": "initial-access",
    "impact": "misc",
}


def _norm_phase(p):
    return _PHASE_NORM.get(p.strip().lower(), "misc")


def _parse_rtk(rtk_root):
    """Red-Teaming-Toolkit: markdown tables |Name|Description|URL| under section headings."""
    readme = os.path.join(rtk_root, "README.md")
    if not os.path.isfile(readme):
        return []
    out = []
    phase = "recon"
    try:
        lines = open(readme, "r", encoding="utf-8", errors="ignore").read().splitlines()
    except OSError:
        return []
    for ln in lines:
        m = re.match(r"^##\s+(.+)$", ln.strip())
        if m and m.group(1).strip().lower() in _PHASE_NORM:
            phase = _norm_phase(m.group(1))
            continue
        cells = [c.strip() for c in ln.strip().strip("|").split("|")]
        if len(cells) >= 3 and cells[0] != "Name" and re.match(r"^https?://", cells[2]):
            out.append({"name": cells[0], "phase": phase,
                        "url": cells[2], "desc": cells[1][:220]})
    return out


def _parse_rtt(rtt_root):
    """RedTeam-Tools: <summary>Category</summary> + setext section headers
    (`Reconnaissance` / `=====`) + `### [🔙](#tool-list)[Name](url)` entries."""
    readme = os.path.join(rtt_root, "README.md")
    if not os.path.isfile(readme):
        return []
    out = []
    phase = "misc"
    try:
        lines = open(readme, "r", encoding="utf-8", errors="ignore").read().splitlines()
    except OSError:
        return []
    n = len(lines)
    for i, ln in enumerate(lines):
        s = re.search(r"<summary>\s*<b>(.*?)</b>", ln)
        if s:
            phase = _norm_phase(s.group(1))
            continue
        # setext heading: "Category" followed by a ==== underline
        if i + 1 < n and re.match(r"^={5,}\s*$", lines[i + 1]):
            m = re.match(r"^([A-Za-z][A-Za-z ]{2,})$", ln.strip())
            if m and m.group(1).strip().lower() in _PHASE_NORM:
                phase = _norm_phase(m.group(1))
                continue
        m = re.search(r"^###.*?\[([^\]]+)\]\((https?://[^)]+)\)", ln)
        if m and "🔙" not in m.group(1) and "tool-list" not in m.group(2):
            name = m.group(1).strip()
            install = None
            # capture the fenced **Install:** block that follows the entry
            j = i + 1
            while j < n and not re.match(r"^### ", lines[j]):
                if "**Install:**" in lines[j]:
                    k = j + 1
                    block = []
                    while k < n and not lines[k].strip().startswith("```"):
                        k += 1
                    k += 1
                    while k < n and not lines[k].strip().startswith("```"):
                        block.append(lines[k].strip())
                        k += 1
                    install = "\n".join(block)[:400]
                    break
                j += 1
            out.append({"name": name, "phase": phase, "url": m.group(2),
                        "desc": f"see {m.group(2)}", "install": install})
    # de-dup by url
    seen, dedup = set(), []
    for e in out:
        if e["url"] in seen:
            continue
        seen.add(e["url"])
        dedup.append(e)
    return dedup


_AWESOME_TOC = ["Initial Access", "Execution", "Persistence", "Privilege Escalation",
                "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
                "Collection", "Exfiltration", "Command and Control",
                "Embedded and Peripheral Devices Hacking", "Misc",
                "RedTeam Gadgets", "Ebooks", "Training", "Certification"]


def _parse_awesome(awesome_root):
    """Awesome-Red-Teaming: ATT&CK-sectioned link catalog (500+ curated resources)."""
    readme = os.path.join(awesome_root, "README.md")
    if not os.path.isfile(readme):
        return []
    out = []
    phase = "misc"
    try:
        lines = open(readme, "r", encoding="utf-8", errors="ignore").read().splitlines()
    except OSError:
        return []
    for ln in lines:
        m = re.match(r"^##\s+\[.*?\]\(.*?\)\s*(.+)$", ln.strip())
        if m:
            phase = _norm_phase(m.group(1))
            continue
        # bullet entries: * [Name](url) or * [Name,](url) or bare [Name](url) lines
        for m in re.finditer(r"\[([^\]\(\)]+)\]\((https?://[^)\s]+)\)", ln):
            name = m.group(1).strip().strip(",")
            url = m.group(2).rstrip(".,)")
            if name and len(name) < 120:
                out.append({"name": name[:90], "phase": phase, "url": url,
                            "desc": f"see {url}"})
    # de-dup by url
    seen, dedup = set(), []
    for e in out:
        if e["url"] in seen:
            continue
        seen.add(e["url"])
        dedup.append(e)
    return dedup


def _parse_backlog(rtt_root):
    """RedTeam-Tools backlog file: category-headed URL list."""
    path = os.path.join(rtt_root, "backlog")
    if not os.path.isfile(path):
        return []
    out = []
    phase = "misc"
    try:
        lines = open(path, "r", encoding="utf-8", errors="ignore").read().splitlines()
    except OSError:
        return []
    for ln in lines:
        s = ln.strip()
        if s and not s.startswith("http") and not s.startswith("-") and " " in s:
            if s.lower() in _PHASE_NORM:
                phase = _norm_phase(s)
        m = re.search(r"(https?://[^\s)]+)", ln)
        if m:
            url = m.group(1).rstrip(".,)")
            name = url.split("//")[-1].split("/")[0].replace("github.com/", "")
            out.append({"name": name[:90], "phase": phase, "url": url,
                        "desc": f"see {url}"})
    seen, dedup = set(), []
    for e in out:
        if e["url"] in seen:
            continue
        seen.add(e["url"])
        dedup.append(e)
    return dedup


class Weapons:
    def __init__(self, roots=None, refresh=False):
        self.roots = roots or {}
        self._entries = None
        self.refresh = refresh

    def _load(self):
        if self._entries is not None:
            return self._entries
        entries = [dict(zip(("name", "phase", "url", "desc"), e), source="builtin")
                   for e in BUILTIN]
        cache_ok = False
        if os.path.isfile(CACHE_FILE) and not self.refresh:
            try:
                with open(CACHE_FILE, "r", encoding="utf-8") as f:
                    cached = json.load(f)
                if cached.get("mtime", 0) > time.time() - 7 * 86400:
                    entries += [dict(e, source="corpus") for e in cached["entries"]]
                    cache_ok = True
            except Exception:
                pass
        if not cache_ok:
            parsed = []
            if "toolkit" in self.roots:
                parsed += _parse_rtk(self.roots["toolkit"])
            if "redteam-tools" in self.roots:
                parsed += _parse_rtt(self.roots["redteam-tools"])
                parsed += _parse_backlog(self.roots["redteam-tools"])
            if "awesome" in self.roots:
                parsed += _parse_awesome(self.roots["awesome"])
            os.makedirs(CACHE_DIR, exist_ok=True)
            try:
                with open(CACHE_FILE, "w", encoding="utf-8") as f:
                    json.dump({"mtime": time.time(), "entries": parsed}, f)
            except OSError:
                pass
            entries += [dict(e, source="corpus") for e in parsed
                        if e["url"] not in {x["url"] for x in entries}]
        self._entries = entries
        return entries

    def search(self, query="", phase=None, limit=25):
        q = query.lower().strip()
        qtoks = set(re.findall(r"[a-z0-9]+", q))
        scored = []
        for e in self._load():
            if phase and e["phase"] != phase:
                continue
            hay = f"{e['name']} {e['desc']}".lower()
            if not qtoks:
                scored.append((1, e))
                continue
            s = 0
            for tok in qtoks:
                if tok in hay:
                    s += 1
            if s:
                scored.append((s, e))
        scored.sort(key=lambda x: (-x[0], x[1]["name"]))
        return [e for _s, e in scored[:limit]]

    def by_phase(self, phase, limit=30):
        return self.search(phase=phase, limit=limit)

    def phases(self):
        ph = {}
        for e in self._load():
            ph.setdefault(e["phase"], 0)
            ph[e["phase"]] += 1
        return ph

    def summary(self):
        ph = self.phases()
        n = sum(ph.values())
        lines = [f"weapons rack: {n} entries"]
        for k in sorted(ph):
            lines.append(f"  {k:18s} {ph[k]}")
        return "\n".join(lines)


def cli_weapons(args):
    from .knowledge import corpus_roots
    w = Weapons(corpus_roots(), refresh=args.refresh)
    if args.phases:
        print(w.summary())
        return
    results = w.search(" ".join(args.query) if args.query else "", phase=args.phase,
                       limit=args.limit)
    if not results:
        print("no matches")
        return
    for e in results:
        print(f"[{e['phase']:16s}] {e['name']}  ({e['source']})")
        print(f"    {e['url']}")
        if e.get("install"):
            print(f"    install: {e['install'][:160].replace(chr(10), ' ; ')}")
        elif e.get("desc"):
            print(f"    {e['desc'][:140]}")


def build_arg_parser(sub):
    p = sub.add_parser("weapons", help="weapons/tool catalog from the corpus")
    p.add_argument("query", nargs="*", default=[])
    p.add_argument("--phase", default=None, help="filter by phase")
    p.add_argument("--limit", type=int, default=25)
    p.add_argument("--phases", action="store_true", help="summary by phase")
    p.add_argument("--refresh", action="store_true", help="re-parse corpus catalogs")
    p.set_defaults(fn=cli_weapons)
    return p
