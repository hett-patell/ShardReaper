#!/usr/bin/env python3
"""
canary.py — the listener-callback canary.

Post-Cobblestone lesson 3: the admin bot lived on an endpoint that was read
and dismissed as "prepared, safe" without ever sending it a canary URL.
Standing rule, now enforced by tooling: EVERY URL-accepting endpoint gets a
unique-token canary callback before it is written off. This module runs the
listener; each candidate endpoint gets its own token and its own log.
"""
import argparse
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEFAULT_OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "data", "canary-hits.jsonl")


def canary_url(host, port, token):
    return f"http://{host}:{port}/{token}"


class _Handler(BaseHTTPRequestHandler):
    hits = None      # shared list [(ts, method, path, headers, body)]
    token = None
    quiet = False

    def _log_hit(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)[:2000] if length else b""
        rec = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "method": self.command,
            "path": self.path,
            "source": self.client_address[0],
            "headers": {k: v for k, v in self.headers.items()},
            "body": body.decode("utf-8", errors="replace"),
        }
        _Handler.hits.append(rec)
        if _Handler.token and _Handler.token in self.path:
            print(f"[canary] *** HIT with token {_Handler.token} from "
                  f"{self.client_address[0]} — {self.command} {self.path}", flush=True)
        elif not _Handler.quiet:
            print(f"[canary] hit {self.client_address[0]} {self.command} "
                  f"{self.path[:80]}", flush=True)

    def do_GET(self):
        self._log_hit()
        self._reply()

    def do_POST(self):
        self._log_hit()
        self._reply()

    def do_HEAD(self):
        self._log_hit()
        self._reply()

    def _reply(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):   # silence the default stderr line
        pass


def run_listener(host="0.0.0.0", port=8888, token=None, out=None, quiet=False):
    """Blocking listener; writes every hit to the JSONL out-file. Ctrl-C to stop."""
    out = out or DEFAULT_OUT
    os.makedirs(os.path.dirname(out), exist_ok=True)
    _Handler.hits = []
    _Handler.token = token
    _Handler.quiet = quiet
    server = ThreadingHTTPServer((host, port), _Handler)
    print(f"[canary] listening on {host}:{port} — callback URL: "
          f"{canary_url('<your-ip>', port, token or '')}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        with open(out, "a", encoding="utf-8") as f:
            for rec in _Handler.hits:
                f.write(json.dumps(rec) + "\n")
        print(f"[canary] {len(_Handler.hits)} hit(s) logged to {out}")
    return 0


def cli_canary(args):
    return run_listener(args.host, args.port, args.token, args.out, args.quiet)


def build_arg_parser(sub):
    p = sub.add_parser("canary", help="listener-callback canary — every "
                        "URL-accepting endpoint gets a token before being "
                        "written off (post-Cobblestone lesson 3)")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8888)
    p.add_argument("--token", default=None, help="unique token per endpoint "
                   "(hits carrying it are flagged loudly)")
    p.add_argument("--out", default=None, help="hits log (default: data/canary-hits.jsonl)")
    p.add_argument("--quiet", action="store_true", help="only report token hits")
    p.set_defaults(fn=cli_canary)
    return p
