#!/usr/bin/env python3
"""
transport.py — own-side transport self-check.

Post-Cobblestone lesson 4: ~2.5 hours in "firewall ban" cooldown while the
real fault was a SIGSTOP'd openvpn. Before assuming target-side blocking,
verify the tunnel's DATA PATH: process state, interface, gateway, DNS.
"""
import os
import re
import socket
import subprocess

VPN_PROCESSES = ("openvpn", "wireguard", "wg-quick", "zerotier-one", "tailscaled")
TUN_PATTERNS = (r"^(tun\d+|tap\d+|wg\d+|zt[a-z0-9]+|tailscale\d+)",
                r"^(tun\d+|tap\d+)")


def _pgrep(name):
    try:
        p = subprocess.run(["pgrep", "-f", name], capture_output=True, text=True,
                           timeout=5)
        return [pid for pid in p.stdout.split() if pid.strip()]
    except (OSError, subprocess.TimeoutExpired):
        return []


def _interfaces():
    ifaces = []
    try:
        with open("/proc/net/dev", "r") as f:
            for line in f:
                m = re.match(r"\s*([a-z0-9]+):", line)
                if m:
                    ifaces.append(m.group(1))
    except OSError:
        pass
    return ifaces


def _default_gateway():
    try:
        with open("/proc/net/route", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 11 and parts[1] == "00000000":
                    gw_hex = parts[2]
                    gw = ".".join(str(int(gw_hex[i:i + 2], 16))
                                  for i in (6, 4, 2, 0))
                    return gw, parts[0]
    except OSError:
        pass
    return None, None


def _tcp_probe(host, port, timeout=2.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _dns():
    try:
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(3)
        try:
            socket.getaddrinfo("example.com", None)
            return True
        finally:
            socket.setdefaulttimeout(old)
    except OSError:
        return False


def healthcheck():
    """Deterministic transport self-check. Returns dict + printable lines.
    Also runs the rack structural check (lesson 15): no methods nested
    inside module functions — the rack is only "fixed" when it is tested."""
    out = {}
    vpn = {}
    for name in VPN_PROCESSES:
        pids = _pgrep(name)
        if pids:
            vpn[name] = pids
    out["vpn_processes"] = vpn
    ifaces = _interfaces()
    out["interfaces"] = ifaces
    out["tun_present"] = [i for i in ifaces if re.match(
        r"^(tun|tap|wg|zt|tailscale)", i)]
    out["tun_device"] = os.path.exists("/dev/net/tun")
    gw, gw_if = _default_gateway()
    out["gateway"] = gw
    out["gateway_if"] = gw_if
    out["gateway_tcp"] = _tcp_probe(gw, 53) if gw else False
    out["gateway_tcp22"] = _tcp_probe(gw, 22) if gw else False
    out["dns"] = _dns()
    # rack structural check: nested defs are where a previous pass stashed
    # a helper the runner never re-discovers — cost us real engagement time
    try:
        from .rackcheck import rack_check
        report = rack_check()
        out["rack"] = {"violations": report["structural_violations"],
                       "pkill_violations": report["pkill_violations"],
                       "ok": report["structural_ok"] and report["pkill_ok"]}
    except Exception as e:
        out["rack"] = {"violations": [], "pkill_violations": [],
                       "ok": False, "error": str(e)}
    return out


def format_health(report):
    lines = ["TRANSPORT SELF-CHECK"]
    lines.append(f"  vpn processes: {report['vpn_processes'] or 'NONE'}")
    lines.append(f"  tunnel interfaces: {report['tun_present'] or 'NONE'}")
    lines.append(f"  /dev/net/tun: {'present' if report['tun_device'] else 'missing'}")
    lines.append(f"  default gateway: {report['gateway']} on {report['gateway_if']}")
    lines.append(f"  gateway tcp/53: {'up' if report['gateway_tcp'] else 'DOWN'} · "
                 f"tcp/22: {'up' if report['gateway_tcp22'] else 'DOWN'}")
    lines.append(f"  dns: {'up' if report['dns'] else 'DOWN'}")
    rack = report.get("rack", {})
    if rack:
        lines.append(f"  rack structure: "
                     f"{'CLEAN' if rack.get('ok') else f'{len(rack.get('violations', []))} nested-def + {len(rack.get('pkill_violations', []))} raw-pkill violation(s)'}")
        for v in rack.get("violations", [])[:5]:
            lines.append(f"    !! {v}")
        for v in rack.get("pkill_violations", [])[:5]:
            lines.append(f"    !! raw pkill -f: {v.get('source')} {v.get('pattern')}")
    verdict = []
    if not report["vpn_processes"] and not report["tun_present"]:
        verdict.append("no VPN process and no tunnel interface — if this "
                       "engagement expects a tunnel, STOP and fix it before "
                       "interpreting anything as target-side blocking")
    if report["gateway"] and not (report["gateway_tcp"] or report["gateway_tcp22"]):
        verdict.append("gateway does not answer — own-side path is down")
    if not report["dns"]:
        verdict.append("DNS is down")
    lines.append(f"  verdict: {'; '.join(verdict) if verdict else 'transport path looks up'}")
    return "\n".join(lines)


def cli_healthcheck(args):
    print(format_health(healthcheck()))
    return 0


# ---------------- transport watchdog (lesson 23) ----------------
def revalidate_targets(eng, timeout=5, log=None):
    """Target re-validation after an infrastructure event: does each host
    still resolve, and do its known ports still answer? Returns a per-host
    report — a redeploy to a new IP shows up as a changed surface, not as
    a mystery."""
    log = log or (lambda m: None)
    out = {}
    for t in eng.state.get("targets", []):
        host = t.get("host") or ""
        if not host:
            continue
        addrs = []
        try:
            old = socket.getdefaulttimeout()
            socket.setdefaulttimeout(min(timeout, 4))
            try:
                infos = socket.getaddrinfo(host, None)
            finally:
                socket.setdefaulttimeout(old)
            addrs = list(dict.fromkeys(i[4][0] for i in infos))
        except OSError:
            pass
        ports = {}
        for p in sorted((t.get("ports") or {}).keys())[:12]:
            ports[str(p)] = _tcp_probe(host, p, timeout=timeout)
        urls = []
        for u in t.get("urls", []):
            url = u.get("url") or ""
            if url:
                urls.append(_probe_url(url, timeout=timeout))
        rec = {"host": host, "addrs": addrs,
               "ports_up": [p for p, ok in ports.items() if ok],
               "ports_down": [p for p, ok in ports.items() if not ok],
               "urls": [u for u in urls if u.get("status")],
               "reached": bool(addrs) and any(ports.values())}
        out[host] = rec
        log(f"revalidate {host}: {len(addrs)} addr(s), "
            f"{len(rec['ports_up'])}/{len(ports)} ports up, "
            f"{len(rec['urls'])} url(s) answering")
    return out


def _probe_url(url, timeout=5):
    from .http import OriginTransport
    t = OriginTransport(timeout=timeout, insecure=True)
    try:
        r = t.request("GET", url, context="anon")
        m = re.search(r"<title[^>]*>([^<]*)", r.get("body", ""), re.I)
        return {"url": url, "status": r.get("status"),
                "title": (m.group(1)[:60] if m else "")}
    except OSError as e:
        return {"url": url, "status": None, "error": str(e)[:80]}


class Watchdog:
    """Transport watchdog with auto-reconnect and target re-validation
    (lesson 23): VPN drops and target redeploys are ASSUMED, not hoped
    away. On a failed round: run the operator's reconnect command, then
    re-validate every known target so a redeploy costs chain RE-EXECUTION,
    not re-discovery."""

    def __init__(self, eng=None, reconnect=None, interval=30, timeout=5,
                 log=None):
        self.eng = eng
        self.reconnect = reconnect
        self.interval = interval
        self.timeout = timeout
        self.log = log or (lambda m: None)
        self.rounds = 0
        self.reconnects = 0

    def round(self):
        self.rounds += 1
        report = healthcheck()
        reasons = []
        if not report["vpn_processes"] and not report["tun_present"]:
            reasons.append("no tunnel")
        if report["gateway"] and not (report["gateway_tcp"]
                                      or report["gateway_tcp22"]):
            reasons.append("gateway down")
        if not report["dns"]:
            reasons.append("dns down")
        healthy = not reasons
        verdict = "; ".join(reasons)
        revalidated = None
        if not healthy and self.reconnect:
            self.reconnects += 1
            self.log(f"watchdog round {self.rounds}: transport DOWN "
                     f"({verdict}) — reconnecting: {self.reconnect}")
            try:
                subprocess.run(["sh", "-c", self.reconnect],
                               capture_output=True, text=True, timeout=60)
            except (subprocess.TimeoutExpired, OSError) as e:
                self.log(f"watchdog: reconnect failed: {e}")
        if not healthy and self.eng is not None:
            self.log(f"watchdog round {self.rounds}: re-validating targets")
            revalidated = revalidate_targets(self.eng, timeout=self.timeout,
                                             log=self.log)
        return {"round": self.rounds, "healthy": healthy,
                "verdict": verdict,
                "reconnect_ran": not healthy and bool(self.reconnect),
                "revalidated": revalidated}

    def run(self, rounds=None, once=False):
        import time as _time
        while True:
            result = self.round()
            if once or (rounds is not None and self.rounds >= rounds):
                return result
            _time.sleep(self.interval)


def cli_watchdog(args):
    from .state import Engagement
    base = os.path.abspath(args.dir)
    eng = None
    if os.path.isfile(os.path.join(base, "state.json")):
        eng = Engagement.load(base)
    else:
        print(f"no engagement at {base} — revalidation disabled, "
              f"transport-only watchdog")
    w = Watchdog(eng=eng, reconnect=args.reconnect, interval=args.interval,
                 timeout=args.timeout, log=lambda m: print(f"[watchdog] {m}"))
    result = w.run(rounds=args.rounds, once=args.once)
    print(f"watchdog stopped after {result['round']} round(s) — "
          f"{'transport UP' if result['healthy'] else 'transport DOWN: ' + result['verdict']}"
          f", reconnects: {w.reconnects}")
    return 0 if result["healthy"] else 1


def build_arg_parser(sub):
    p = sub.add_parser("healthcheck", help="own-side transport self-check: "
                        "vpn process, tunnel, gateway, dns (lesson 4)")
    p.set_defaults(fn=cli_healthcheck)

    w = sub.add_parser("watchdog", help="transport watchdog: auto-reconnect "
                       "on tunnel failure + target re-validation (lesson 23)")
    w.add_argument("dir", help="engagement folder (for target re-validation)")
    w.add_argument("--reconnect", default=None,
                   help="reconnect command, e.g. 'systemctl restart openvpn@lab'")
    w.add_argument("--interval", type=float, default=30,
                   help="seconds between rounds")
    w.add_argument("--rounds", type=int, default=None,
                   help="stop after N rounds")
    w.add_argument("--once", action="store_true", help="single round")
    w.add_argument("--timeout", type=float, default=5)
    w.set_defaults(fn=cli_watchdog)
    return p
