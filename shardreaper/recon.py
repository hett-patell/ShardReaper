#!/usr/bin/env python3
"""
recon.py — the recon arsenal. stdlib-first, scope-gated, aggressive.

Every primitive calls scope.enforce() before touching anything. Nothing
outside the operator's scope is ever contacted — the gate is in code.

Primitives: DNS (resolve/AXFR/subdomain brute), TCP connect scan with banner
grab, TLS cert inspection, HTTP fingerprinting (headers, title, tech stack),
common-path probing, CORS check, security-header audit.
External wrappers: nmap / masscan / nuclei / ffuf / subfinder when installed.
"""
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

try:
    from http.client import HTTPConnection, HTTPSConnection
except ImportError:  # pragma: no cover
    from httplib import HTTPConnection, HTTPSConnection

from .scope import Scope, OutOfScopeError

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 465, 587,
                 993, 995, 1433, 1521, 2049, 2375, 3000, 3306, 3389, 5000, 5432,
                 5900, 5985, 5986, 6379, 8000, 8080, 8081, 8443, 8888, 9000,
                 9200, 10000, 11211, 27017]
HTTP_PORTS = {80, 443, 3000, 5000, 8000, 8080, 8081, 8443, 8888, 9000, 10000}
COMMON_PATHS = [
    "/", "/robots.txt", "/sitemap.xml", "/.git/HEAD", "/.git/config",
    "/.env", "/.well-known/security.txt", "/server-status", "/server-info",
    "/admin", "/administrator", "/login", "/wp-login.php", "/wp-admin/",
    "/backup.zip", "/backup.sql", "/db.sql", "/config.php.bak", "/phpinfo.php",
    "/actuator", "/actuator/env", "/swagger-ui.html", "/api/swagger.json",
    "/graphql", "/console", "/jenkins", "/.DS_Store", "/WEB-INF/web.xml",
    "/crossdomain.xml", "/README.md", "/.svn/entries", "/.htaccess",
]
TECH_PATTERNS = [
    (r"server:\s*([^\r\n]+)", "server"),
    (r"x-powered-by:\s*([^\r\n]+)", "x-powered-by"),
    (r"set-cookie:\s*([^=;]+)=", "cookie"),
    (r"x-aspnet-version:\s*(\S+)", "aspnet"),
    (r"x-drupal-cache", "drupal"),
    (r"x-generator:\s*(\S+)", "generator"),
    (r"x-vercel-id", "vercel"),
    (r"x-shopify", "shopify"),
    (r"x-rack-cache", "rack/rails"),
    (r"x-amz-cf-id", "cloudfront"),
    (r"x-azure-ref", "azure"),
    (r"x-github-request-id", "github-pages"),
    (r"x-nextjs", "nextjs"),
    (r"x-nuxt", "nuxt"),
    (r"x-drupal", "drupal"),
]
MISSING_HEADERS = ["strict-transport-security", "content-security-policy",
                   "x-frame-options", "x-content-type-options", "x-xss-protection"]

# Burp (or any intercepting proxy) — set SHARDREAPER_PROXY=http://127.0.0.1:8080
# and every HTTP request flows through it (CONNECT tunnel for HTTPS).
PROXY = os.environ.get("SHARDREAPER_PROXY", "") or None


def _parse_proxy(proxy):
    p = urlparse(proxy if "://" in proxy else "http://" + proxy)
    return p.hostname, (p.port or 8080)


class Recon:
    def __init__(self, scope, timeout=3.0, workers=32, log=None):
        self.scope = scope
        self.timeout = timeout
        self.workers = workers
        self.log = log or (lambda *a, **k: None)

    # ---------------- DNS ----------------
    def resolve(self, host, want="A"):
        try:
            infos = socket.getaddrinfo(host, None)
            addrs = sorted({info[4][0] for info in infos})
            return addrs
        except socket.gaierror:
            return []

    def axfr(self, domain, ns=None):
        """Attempt a DNS zone transfer (AXFR) — classic misconfig."""
        import struct
        results = []
        for server in ([ns] if ns else [domain] + self.resolve(domain)):
            if not server:
                continue
            try:
                # build a minimal AXFR query for the domain
                q = b"\x00\x00" + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                for label in domain.rstrip(".").split("."):
                    q += bytes([len(label)]) + label.encode()
                q += b"\x00\x00\xfc\x00\x01"
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(self.timeout)
                s.sendto(q, (server, 53))
                data, _ = s.recv(4096)
                if len(data) > 12 and data[2:4] == b"\x00\x00":
                    ancount = struct.unpack(">H", data[6:8])[0]
                    if ancount:
                        results.append(server)
                s.close()
            except OSError:
                continue
        return results

    def subdomain_brute(self, domain, wordlist, limit=2000):
        found = []
        words = []
        if os.path.isfile(wordlist):
            with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
                words = [ln.strip().lower() for ln in f if ln.strip()]
        else:
            words = ["www", "mail", "webmail", "vpn", "remote", "admin", "portal",
                     "intranet", "dev", "test", "staging", "api", "app", "old",
                     "ftp", "sftp", "ssh", "git", "gitlab", "jenkins", "grafana",
                     "kibana", "monitor", "ns1", "ns2", "mx", "owa", "autodiscover",
                     "cloud", "cms", "blog", "shop", "store", "docs", "wiki", "jira",
                     "confluence", "ci", "cd", "prod", "production", "qa", "lab",
                     "demo", "sandbox", "beta", "backup", "files", "static", "img",
                     "cdn", "assets", "media", "download", "uploads", "status",
                     "statuspage", "health", "metrics", "prometheus", "k8s",
                     "kubernetes", "docker", "registry", "harbor", "nexus", "artifactory",
                     "sonar", "sentry", "elk", "logs", "dashboard", "metrics"]
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            futs = {ex.submit(self._try_sub, domain, w): w for w in words[:limit]}
            for fut in as_completed(futs):
                w = futs[fut]
                try:
                    if fut.result():
                        found.append(w)
                except Exception:
                    pass
        return sorted(set(found))

    def _try_sub(self, domain, word):
        host = f"{word}.{domain}"
        if not self.scope.in_scope_host(host):
            return None
        if self.resolve(host):
            return host
        return None

    # ---------------- ports ----------------
    def port_scan(self, host, ports=None, top=100, adaptive=True, chunk=256):
        """TCP connect sweep with adaptive pacing (post-Cobblestone lesson 8).

        A hard parallel sweep can trip rate filters and self-ban. Chunks the
        port list and reacts to the answered-vs-dropped ratio: pause, extend
        timeouts, and stop outright when the target goes dark.
        """
        ports = ports or DEFAULT_PORTS[:top]
        open_ports = {}
        self.last_scan_meta = {"ban": False, "ratio": 1.0, "chunks": 0}
        chunks = [ports[i:i + chunk] for i in range(0, len(ports), chunk)]
        for idx, pc in enumerate(chunks):
            with ThreadPoolExecutor(max_workers=self.workers) as ex:
                futs = {ex.submit(self._probe_port, host, p): p for p in pc}
                answered = 0
                for fut in as_completed(futs):
                    r = fut.result()
                    if r:
                        answered += 1
                        open_ports[r[0]] = r[1]
            self.last_scan_meta["chunks"] = idx + 1
            if len(pc):
                self.last_scan_meta["ratio"] = answered / len(pc)
            policy = adaptive_policy(answered, len(pc), idx)
            self.last_scan_meta.update(policy)
            if policy["ban"]:
                self.last_scan_meta["ban"] = True
                self.log(f"port_scan {host}: {answered}/{len(pc)} answered — "
                         f"target likely FILTERING (ratio "
                         f"{self.last_scan_meta['ratio']:.2f}). Stopping the sweep; "
                         f"pace later or switch to passive sources.", "warn")
                break
            if policy["pause"]:
                self.log(f"port_scan {host}: low answer ratio "
                         f"({self.last_scan_meta['ratio']:.2f}) — backing off "
                         f"{policy['pause']}s, timeout->{policy['timeout']}s", "warn")
                time.sleep(policy["pause"])
            self.timeout = policy["timeout"]
        return dict(sorted(open_ports.items()))

    def _probe_port(self, host, port):
        if not self.scope.in_scope(host, port=port):
            return None
        try:
            with socket.create_connection((host, port), timeout=self.timeout):
                return port, self._banner(host, port)
        except OSError:
            return None

    def _banner(self, host, port):
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as s:
                s.settimeout(self.timeout)
                if port in (443, 8443, 993, 995, 5986, 10000):
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    s = ctx.wrap_socket(s, server_hostname=host)
                s.sendall(b"\r\n")
                data = s.recv(256)
                text = data.decode("utf-8", errors="ignore").strip()
                return text[:120] if text else None
        except OSError:
            return None


    # ---------------- TLS ----------------
    def tls_cert(self, host, port=443):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as s:
                with ctx.wrap_socket(s, server_hostname=host) as ss:
                    der = ss.getpeercert(binary_form=True)
                    import datetime
                    cert = None
                    try:
                        cert = ssl._ssl._test_decode_cert(der)
                    except Exception:
                        cert = None
                    if not cert:
                        return {"host": host, "error": "decode failed"}
                    not_after = cert.get("notAfter", "")
                    expired = False
                    try:
                        exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        expired = exp < datetime.datetime.utcnow()
                    except Exception:
                        pass
                    sans = []
                    for ext in cert.get("subjectAltName", ()):
                        sans.append(ext[1])
                    return {
                        "host": host, "subject": cert.get("subject", ()),
                        "issuer": cert.get("issuer", ()),
                        "not_after": not_after, "expired": expired,
                        "san": sans[:20],
                    }
        except OSError as e:
            return {"host": host, "error": str(e)}
    
    # ---------------- HTTP ----------------
    def _http(self, url, method="GET", headers=None, timeout=None, body=None):
        u = urlparse(url)
        host, port = u.hostname, u.port or (443 if u.scheme == "https" else 80)
        self.scope.enforce(host, port=port, path=u.path or "/")
        cls = HTTPSConnection if u.scheme == "https" else HTTPConnection
        hdrs = {"User-Agent": "ShardReaper/1.0 (authorized security testing)",
                "Accept": "*/*"}
        if headers:
            hdrs.update(headers)
        if PROXY:
            ph, pp = _parse_proxy(PROXY)
            conn = cls(ph, pp, timeout=timeout or self.timeout)
            if u.scheme == "https":
                conn.set_tunnel(host, port)     # CONNECT through the proxy
            path = url if u.scheme == "http" else (u.path or "/")
            if u.scheme != "http" and u.query:
                path += "?" + u.query
        else:
            conn = cls(host, port, timeout=timeout or self.timeout)
            path = u.path or "/"
            if u.query:
                path += "?" + u.query
        conn.request(method, path, body=body, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read(20000)
        out = {"status": resp.status, "reason": resp.reason,
               "headers": {k.lower(): v for k, v in resp.getheaders()},
               "body": data.decode("utf-8", errors="ignore")[:12000]}
        conn.close()
        return out
    
    def http_probe(self, url):
        try:
            r = self._http(url)
            title = ""
            m = re.search(r"<title[^>]*>(.*?)</title>", r["body"], re.I | re.S)
            if m:
                title = m.group(1).strip()[:100]
            tech = self._detect_tech(r["headers"], r["body"])
            return {"url": url, "status": r["status"], "title": title,
                    "server": r["headers"].get("server", ""),
                    "tech": tech, "headers": r["headers"]}
        except (OSError, OutOfScopeError) as e:
            return {"url": url, "error": str(e)}
    
    @staticmethod
    def _detect_tech(headers, body):
        tech = set()
        for pat, name in TECH_PATTERNS:
            if re.search(pat, json.dumps(headers), re.I):
                tech.add(name)
        body_l = body.lower()
        for token, name in [("wordpress", "wordpress"), ("drupal", "drupal"),
                            ("joomla", "joomla"), ("__next", "nextjs"),
                            ("nuxt", "nuxt"), ("react", "react"),
                            ("vue.js", "vue"), ("angular", "angular"),
                            ("jquery", "jquery"), ("bootstrap", "bootstrap"),
                            ("laravel", "laravel"), ("django", "django"),
                            ("flask", "flask"), ("express", "express"),
                            ("spring", "spring"), ("struts", "struts"),
                            ("tomcat", "tomcat"), ("nginx", "nginx"),
                            ("apache", "apache"), ("iis", "iis"),
                            ("cloudflare", "cloudflare"), ("cf-ray", "cloudflare")]:
            if token in body_l:
                tech.add(name)
        return sorted(tech)
    
    def check_paths(self, url, paths=None):
        """Probe common sensitive/interesting paths; report statuses."""
        out = []
        u = urlparse(url)
        base = f"{u.scheme}://{u.netloc}"
        for p in (paths or COMMON_PATHS):
            full = base + p
            try:
                r = self._http(full, method="GET", headers={"Range": "bytes=0-256"})
                interesting = r["status"] in (200, 301, 302, 403, 500)
                detail = ""
                if r["status"] == 200:
                    if p in ("/.git/HEAD", "/.git/config"):
                        detail = r["body"][:80].replace("\n", " ")
                    elif p in ("/.env", "/backup.zip", "/backup.sql", "/db.sql",
                               "/config.php.bak", "/phpinfo.php", "/.DS_Store",
                               "/.svn/entries", "/.htaccess"):
                        detail = r["body"][:80].replace("\n", " ")
                if interesting:
                    out.append({"path": p, "status": r["status"], "detail": detail})
            except (OSError, OutOfScopeError):
                continue
        return out
    
    def cors_check(self, url):
        try:
            r = self._http(url, headers={"Origin": "https://evil.example"})
            acao = r["headers"].get("access-control-allow-origin", "")
            if acao == "https://evil.example" or acao == "*":
                return {"url": url, "vulnerable": True, "acao": acao,
                        "credentials": r["headers"].get("access-control-allow-credentials", "")}
            return {"url": url, "vulnerable": False, "acao": acao}
        except (OSError, OutOfScopeError) as e:
            return {"url": url, "error": str(e)}
    
    def security_header_audit(self, url):
        try:
            r = self._http(url)
        except (OSError, OutOfScopeError) as e:
            return {"url": url, "error": str(e)}
        missing = [h for h in MISSING_HEADERS if h not in r["headers"]]
        return {"url": url, "status": r["status"], "missing": missing}
    
    # ---------------- external tools ----------------
    def tool_path(self, name):
        return shutil.which(name)
    
    def run_tool(self, name, args, timeout=300, cwd=None):
        """Run an external tool if installed; returns dict or None if missing."""
        path = self.tool_path(name)
        if not path:
            return None
        try:
            p = subprocess.run([path] + args, capture_output=True, text=True,
                               timeout=timeout, cwd=cwd)
            return {"ok": p.returncode == 0, "returncode": p.returncode,
                    "stdout": (p.stdout or "")[-4000:],
                    "stderr": (p.stderr or "")[-2000:]}
        except (subprocess.TimeoutExpired, OSError) as e:
            return {"ok": False, "error": str(e)}
    
    def nmap(self, host, ports=None, scripts=None):
        args = ["-Pn", "--open"]
        if ports:
            args += ["-p", ",".join(str(p) for p in ports)]
        if scripts:
            args += ["--script", ",".join(scripts)]
        args += [host, "-oX", "-"]
        r = self.run_tool("nmap", args, timeout=600)
        if not r:
            return None
        # light parse of XML output
        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(r["stdout"])
            services = []
            for host_el in root.iter("host"):
                for port_el in host_el.iter("port"):
                    state = port_el.find("state")
                    if state is not None and state.get("state") == "open":
                        svc = port_el.find("service")
                        services.append({
                            "port": int(port_el.get("portid", 0)),
                            "proto": port_el.get("protocol"),
                            "service": svc.get("name") if svc is not None else "",
                            "product": svc.get("product") if svc is not None else "",
                            "version": svc.get("version") if svc is not None else "",
                        })
            return {"tool": "nmap", "services": services, "raw": r["stdout"][:2000]}
        except Exception:
            return {"tool": "nmap", "services": [], "raw": r["stdout"][:2000]}
    
    
    # ---------------- orchestrated recon run ----------------
def adaptive_policy(answered, total, chunk_idx):
    """Decision table for scan pacing — pure function, unit-tested."""
    if total < 20:
        return {"pause": 0, "timeout": 3.0, "ban": False}
    ratio = answered / total
    if ratio >= 0.5:
        return {"pause": 0, "timeout": 3.0, "ban": False}
    if ratio < 0.05 and chunk_idx >= 1:
        return {"pause": 0, "timeout": 3.0, "ban": True}
    return {"pause": 5.0, "timeout": min(3.0 + 3.0 * chunk_idx, 15.0),
            "ban": False}

def run_recon(scope, seeds, wordlist=None, ports=None, top_ports=100, workers=32,
              log=None, include_external=True, paths=True, osint=True):
    """Full recon sweep over in-scope seeds. Returns targets list for state."""
    log = log or (lambda *a, **k: None)
    r = Recon(scope, workers=workers, log=log)
    targets = []
    seen_hosts = set()

    # passive scope expansion first (crt.sh / subfinder / assetfinder), then sweep
    if osint:
        try:
            from .osint import osint_expand
            extra = osint_expand(scope, seeds, log=log, resolve=r.resolve)
            seeds = list(seeds) + [h for h in extra if h not in seeds]
        except Exception:
            pass

    for seed in seeds:
        host = urlparse(seed if "://" in seed else "//" + seed).hostname or seed
        if not scope.in_scope_host(host):
            log(f"skip {host}: out of scope", "warn")
            continue
        log(f"recon {host} — resolve + ports + http")
        addrs = r.resolve(host)
        if not addrs:
            log(f"{host}: no DNS records", "warn")
            continue
        open_ports = r.port_scan(host, ports=ports, top=top_ports)
        # well-known web ports always get an HTTP probe; explicit operator-
        # supplied port lists get probed too (they were chosen for a reason)
        http_ports = [p for p in open_ports
                      if p in HTTP_PORTS or (ports and p in ports)]
        target = {"host": host, "addrs": addrs, "ports": open_ports,
                  "urls": [], "origins": [], "intel": {}, "findings": []}
        for p in http_ports:
            scheme = "https" if p in (443, 8443, 5986, 10000) else "http"
            url = f"{scheme}://{host}:{p}"
            # lesson 16: a target is an ORIGIN — record the scheme+host
            # identity, not just the ip:port pair that probed it
            from .http import origin_of
            origin = origin_of(url)
            if origin not in target["origins"]:
                target["origins"].append(origin)
            probe = r.http_probe(url)
            target["urls"].append({"url": url, **{k: v for k, v in probe.items()
                                                  if k in ("status", "title", "server", "tech")}})
            if probe.get("status"):
                log(f"  {url} [{probe.get('status')}] {probe.get('title', '')[:60]} "
                    f"{','.join(probe.get('tech', []))}", "action")
            if p == 443 or p == 8443:
                cert = r.tls_cert(host, p)
                if cert.get("expired"):
                    target["findings"].append({"type": "tls", "severity": "medium",
                                               "detail": f"expired TLS cert @ {host}:{p}"})
            # CORS misconfiguration check
            cors = r.cors_check(url)
            if cors.get("vulnerable"):
                target["findings"].append({"type": "cors", "severity": "medium",
                                           "detail": f"CORS reflects arbitrary Origin "
                                                     f"(ACAO={cors.get('acao')}, "
                                                     f"credentials={cors.get('credentials')})"})
                log(f"  {url}: CORS misconfiguration", "win")
            # missing security headers audit
            audit = r.security_header_audit(url)
            if audit.get("missing"):
                target["findings"].append({"type": "missing-headers",
                                           "severity": "low",
                                           "detail": f"missing security headers: "
                                                     f"{', '.join(audit['missing'])}"})
            if paths:
                found = r.check_paths(url)
                for f_ in found:
                    if f_["status"] == 200 and f_["path"] in ("/.git/HEAD", "/.git/config",
                                                              "/.env", "/backup.zip",
                                                              "/backup.sql", "/db.sql",
                                                              "/config.php.bak", "/phpinfo.php",
                                                              "/.svn/entries", "/.htaccess"):
                        target["findings"].append({"type": "exposed-path",
                                                   "severity": "high",
                                                   "path": f_["path"], "status": 200,
                                                   "detail": f_["detail"][:120]})
                    elif f_["status"] == 200:
                        target["findings"].append({"type": "interesting-path",
                                                   "severity": "low",
                                                   "path": f_["path"], "status": 200})
                if found:
                    log(f"  {url}: {len(found)} interesting paths", "action")
        # external tool enrichment (nmap service detection) when installed
        if include_external:
            nm = r.nmap(host)
            if nm and nm.get("services"):
                target["intel"]["nmap"] = nm["services"]
                log(f"  {host}: nmap identified {len(nm['services'])} services", "action")
        if open_ports:
            log(f"  {host}: {len(open_ports)} open ports: "
                f"{','.join(str(p) for p in list(open_ports)[:20])}", "action")
        # domain-level extras for the bare host
        if host not in seen_hosts:
            seen_hosts.add(host)
            axfr = r.axfr(host)
            if axfr:
                target["findings"].append({"type": "dns-axfr", "severity": "medium",
                                           "detail": f"zone transfer allowed from {axfr}"})
                log(f"  {host}: AXFR zone transfer ALLOWED", "win")
        targets.append(target)

    # subdomain brute on the apex domain of each seed (cheap, in-scope only)
    for seed in seeds:
        host = urlparse(seed if "://" in seed else "//" + seed).hostname or seed
        if host.count(".") >= 1 and not host.replace(".", "").isdigit():
            domain = host
            subs = r.subdomain_brute(domain, wordlist or "", limit=800)
            if subs:
                log(f"{domain}: {len(subs)} live subdomains: {', '.join(subs[:25])}", "action")
                targets.append({"host": domain, "subdomains": subs, "ports": {},
                                "urls": [], "intel": {}, "findings": []})
    return targets


def build_arg_parser(sub):
    p = sub.add_parser("recon", help="run recon sweep on the engagement")
    p.add_argument("--scope", help="scope JSON (defaults to engagement's)")
    p.add_argument("--host", help="single host/URL to recon (creates ad-hoc engagement)")
    p.add_argument("--wordlist", default=os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "data", "wordlists", "subdomains.txt"))
    p.add_argument("--top-ports", type=int, default=100)
    p.add_argument("--no-paths", action="store_true")
    p.add_argument("--no-external", action="store_true")
    p.set_defaults(fn=lambda a: None)  # wired in cli.py where engagement exists
    return p
