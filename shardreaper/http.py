#!/usr/bin/env python3
"""
http.py — origin-bound HTTP transport (lesson 16).

The framework's old identity model was WRONG: a target is not IP:port, it is
an ORIGIN (scheme + host [+ port]). Virtual-hosted apps route on the Host
header and pin cookies to a domain; a client that connects to an IP while
claiming a Host header — or worse, one that reuses one cookie jar across
hosts — silently drops sessions and poisons jars.

Invariants, enforced here:

1. ONE COOKIE JAR PER ORIGIN. Cookies are keyed by (origin, context); a
   Set-Cookie received on origin A can never be replayed on origin B.
2. ORIGIN-BOUND TRANSPORT WITH --resolve SEMANTICS. Every request takes a
   full origin URL; DNS is resolved HERE (with an operator override map,
   curl --resolve style) and the Host header always carries the origin —
   never the connect-time IP.
3. ANONYMOUS AND AUTHENTICATED TRAFFIC NEVER SHARE A JAR. Every request
   declares a context key (default "anon"); authenticated contexts carry
   their own jar per origin, so a logged-out probe can never inherit — or
   leak — session cookies.
4. Domain pinning is honored: a Set-Cookie without Domain stays pinned to
   its exact host; with Domain=… it applies to the domain and subdomains.
   Path prefixes and expiry are respected.

stdlib-only, deterministic, unit-tested.
"""
import http.cookies
import re
import socket
import ssl
import time
from urllib.parse import urlparse, urlunparse


def origin_of(url):
    """scheme://host[:port] — the identity of an HTTP target. Bare hosts
    default scheme http / port 80 (or 443)."""
    if "://" not in url:
        url = "http://" + url
    u = urlparse(url)
    host = (u.hostname or "").lower()
    if not host:
        raise ValueError(f"no host in {url}")
    port = u.port or (443 if u.scheme == "https" else 80)
    default = (u.scheme == "https" and port == 443) or \
              (u.scheme == "http" and port == 80)
    return f"{u.scheme}://{host}" + ("" if default else f":{port}")


def split_origin(origin):
    u = urlparse(origin)
    port = u.port or (443 if u.scheme == "https" else 80)
    return u.scheme, u.hostname, port


class CookieJar:
    """One jar for one origin. Domain-pinned, path-scoped, expiry-aware."""

    def __init__(self):
        self._c = {}  # (domain, path, name) -> {value, expires, pinned}

    def add(self, set_cookie_lines, origin_host, origin_path):
        for line in set_cookie_lines or []:
            try:
                sc = http.cookies.SimpleCookie()
                sc.load(str(line))
            except (http.cookies.CookieError, ValueError):
                continue
            for name, morsel in sc.items():
                # no Domain attribute -> pinned to the EXACT origin host;
                # Domain=... -> applies to the domain and its subdomains
                pinned = not morsel["domain"]
                domain = (morsel["domain"] or "").lower().lstrip(".")
                domain = domain or origin_host.lower()
                path = morsel["path"] or origin_path or "/"
                expires = None
                if morsel["max-age"]:
                    try:
                        expires = time.time() + int(morsel["max-age"])
                    except ValueError:
                        expires = None
                elif morsel["expires"]:
                    try:
                        t = http.cookies._str_to_time(morsel["expires"])
                        expires = t if t is not None else None
                    except (ValueError, AttributeError):
                        expires = None
                if expires is not None and expires <= time.time():
                    self._c.pop((domain, path, name), None)
                    continue
                self._c[(domain, path, name)] = {
                    "value": morsel.value or "", "expires": expires,
                    "pinned": pinned}

    def header(self, host, path, secure):
        now = time.time()
        out = []
        host = (host or "").lower()
        for (domain, cpath, name), c in list(self._c.items()):
            if c["expires"] is not None and c["expires"] <= now:
                self._c.pop((domain, cpath, name), None)
                continue
            if c.get("pinned"):
                if host != domain:
                    continue
            elif not _host_matches(host, domain):
                continue
            if not path.startswith(cpath or "/"):
                continue
            out.append(f"{name}={c['value']}")
        return "; ".join(out) or None


def _host_matches(host, domain):
    if host == domain:
        return True
    return host.endswith("." + domain)


class OriginTransport:
    """Origin-bound HTTP client: resolve here, Host from the origin,
    per-(origin, context) cookie jars."""

    def __init__(self, timeout=10, insecure=False, resolve=None):
        self.timeout = timeout
        self.insecure = insecure
        self.resolve = dict(resolve or {})   # host -> ip (--resolve semantics)
        self._dns = {}                       # host -> [ips] cache
        self._jars = {}                      # (origin, ctx) -> CookieJar

    def add_resolve(self, host, ip):
        self.resolve[host.lower()] = ip
        self._dns.pop(host.lower(), None)

    def jar_for(self, origin, context="anon"):
        key = (origin, context)
        return self._jars.setdefault(key, CookieJar())

    def _connect_ip(self, host, port):
        if self.resolve.get(host):
            return socket.create_connection((self.resolve[host], port),
                                            timeout=self.timeout)
        if host not in self._dns:
            old = socket.getdefaulttimeout()
            socket.setdefaulttimeout(min(self.timeout, 5))
            try:
                infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
            finally:
                socket.setdefaulttimeout(old)
            self._dns[host] = list(dict.fromkeys(i[4][0] for i in infos))
        for ip in self._dns[host]:
            try:
                return socket.create_connection((ip, port), timeout=self.timeout)
            except OSError:
                continue
        raise OSError(f"cannot connect to {host}:{port}")

    def request(self, method, url, headers=None, body=None, context="anon",
                follow=0, insecure=None, host_header=None):
        """One request on the origin-bound transport. `context` selects the
        cookie jar — "anon" by default; pass e.g. "user:admin" for an
        authenticated identity. The jar is per (origin, context): anonymous
        and authenticated traffic NEVER share cookies."""
        if "://" not in url:
            url = "http://" + url
        u = urlparse(url)
        scheme = u.scheme or "http"
        host = (u.hostname or "").lower()
        if not host:
            raise ValueError(f"no host in {url}")
        port = u.port or (443 if scheme == "https" else 80)
        path = u.path or "/"
        if u.query:
            path += "?" + u.query
        origin = origin_of(urlunparse((scheme, u.netloc, "", "", "", "")))
        jar = self.jar_for(origin, context)
        hdrs = dict(headers or {})
        host_value = host_header or (host if port in (80, 443) else
                                     f"{host}:{port}")
        hdrs.setdefault("Host", host_value)
        cookie = jar.header(host, u.path or "/", scheme == "https")
        if cookie:
            hdrs["Cookie"] = cookie
        use_tls = scheme == "https"
        use_insecure = self.insecure if insecure is None else insecure
        sock = self._connect_ip(host, port)
        try:
            if use_tls:
                ctx = ssl._create_unverified_context() if use_insecure \
                    else ssl.create_default_context()
                sock = ctx.wrap_socket(sock, server_hostname=host)
            req = [f"{method} {path} HTTP/1.1"]
            for k, v in hdrs.items():
                req.append(f"{k}: {v}")
            if body is not None:
                req.append(f"Content-Length: {len(body)}")
            req += ["Connection: close", "", ""]
            sock.sendall("\r\n".join(req).encode("utf-8", "ignore"))
            if body:
                sock.sendall(body)
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
            head, _, rest = buf.partition(b"\r\n\r\n")
            lines = head.decode("utf-8", "ignore").split("\r\n")
            status = int(lines[0].split()[1]) if lines and \
                len(lines[0].split()) > 1 else 0
            resp_headers = {}
            set_cookies = []
            for ln in lines[1:]:
                if ":" not in ln:
                    continue
                k, v = ln.split(":", 1)
                k, v = k.strip().lower(), v.strip()
                if k == "set-cookie":
                    set_cookies.append(v)
                else:
                    resp_headers[k] = v
            if set_cookies:
                jar.add(set_cookies, host, u.path or "/")
            # content-length read (Connection: close keeps this simple)
            length = int(resp_headers.get("content-length", "0") or "0")
            payload = rest
            while length and len(payload) < length:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                payload += chunk
            out = {"status": status, "headers": resp_headers,
                   "set_cookies": set_cookies,
                   "body": payload.decode("utf-8", "ignore"),
                   "raw": payload, "origin": origin, "context": context}
            if follow and status in (301, 302, 303, 307, 308):
                loc = resp_headers.get("location")
                if loc:
                    if loc.startswith("/"):
                        loc = origin + loc
                    if follow > 0:
                        return self.request(method if status == 307 else "GET",
                                            loc, context=context,
                                            follow=follow - 1)
                    out["redirect"] = loc
            return out
        finally:
            try:
                sock.close()
            except OSError:
                pass
