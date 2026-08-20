#!/usr/bin/env python3
"""
gitmine.py — git hosts are a recon category, not a one-off (lesson 21).

For every Gitea / GitLab / GitHub / Bitbucket surface on a target:
enumerate users / orgs / repos, walk commit history, and hunt deleted
secrets — ALWAYS via blob hashes, because raw file endpoints lie about
refs (a raw fetch at a ref gives the ref's current content, not the
deleted-secret history). Secret content is fetched by object hash through
the platform's git blobs API, and commit diffs are pulled so removed
secrets are diffed out of history.

stdlib-only. Every API call goes through an injectable `api` function, so
the module is fully testable offline; on live targets it degrades loudly
(404/401 are per-endpoint skips, never fatal).
"""
import base64
import json
import re
from urllib.parse import quote

# each platform: detect probe, api root suffix, endpoints, auth header style
# (every path is ROOT-RELATIVE; _ApiCaller prepends the platform root)
PLATFORMS = {
    "gitea": {
        "probe": "/version",
        "root": "/api/v1",
        "auth": "Bearer",
        "users": "/users/search?q={q}&limit={n}",
        "orgs": "/orgs?limit={n}",
        "user_repos": "/users/{u}/repos?limit={n}",
        "org_repos": "/orgs/{o}/repos?limit={n}",
        "commits": "/repos/{o}/{r}/commits?limit={n}",
        "tree": "/repos/{o}/{r}/git/trees/{ref}?recursive=1",
        "blob": "/repos/{o}/{r}/git/blobs/{sha}",
        "commit_diff": "/repos/{o}/{r}/commits/{sha}.diff",
        "blob_field": "content",
    },
    "gitlab": {
        "probe": "/version",
        "root": "/api/v4",
        "auth": "Bearer",
        "users": "/users?search={q}&per_page={n}",
        "orgs": "/groups?per_page={n}",
        "user_repos": "/users/{u}/projects?per_page={n}",
        "org_repos": "/groups/{o}/projects?per_page={n}",
        "commits": "/projects/{p}/repository/commits?per_page={n}",
        "tree": "/projects/{p}/repository/tree?recursive=true",
        "blob": "/projects/{p}/repository/blobs/{sha}",
        "commit_diff": "/projects/{p}/repository/commits/{sha}/diff",
        "blob_field": "content",
    },
    "github": {
        "probe": "/",
        "root": "/api/v3",
        "auth": "Bearer",
        "users": "/search/users?q={q}&per_page={n}",
        "orgs": "/organizations?per_page={n}",
        "user_repos": "/users/{u}/repos?per_page={n}",
        "org_repos": "/orgs/{o}/repos?per_page={n}",
        "commits": "/repos/{o}/{r}/commits?per_page={n}",
        "tree": "/repos/{o}/{r}/git/trees/{ref}?recursive=1",
        "blob": "/repos/{o}/{r}/git/blobs/{sha}",
        "commit_diff": "/repos/{o}/{r}/compare/{base}...{sha}",
        "blob_field": "content",
    },
    "bitbucket": {
        "probe": "/repositories",
        "root": "/2.0",
        "auth": "Bearer",
        "users": "/users?q={q}&pagelen={n}",
        "orgs": "/workspaces?pagelen={n}",
        "user_repos": "/users/{u}/repositories?pagelen={n}",
        "org_repos": "/repositories/{o}?pagelen={n}",
        "commits": "/repositories/{ws}/{slug}/commits?pagelen={n}",
        "tree": "/repositories/{ws}/{slug}/src/{ref}/",
        "blob": None,   # bitbucket has no blob-hash endpoint — noted, not faked
        "commit_diff": "/repositories/{ws}/{slug}/diff/{sha}",
        "blob_field": None,
    },
}

SECRET_PATTERNS = [
    ("aws-key", r"(AKIA|ASIA)[A-Z0-9]{16}"),
    ("github-token", r"gh[pousr]_[A-Za-z0-9]{36,}"),
    ("jwt", r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    ("private-key", r"-----BEGIN (RSA|EC|OPENSSH|DSA) PRIVATE KEY-----"),
    ("ssh-private", r"-----BEGIN OPENSSH PRIVATE KEY-----"),
    ("basic-auth-url", r"[a-z]+://[^/\s:@]+:[^/\s@]+@[^\s]+"),
    ("password-assign", r"(?i)(password|passwd|pwd|secret|api[_-]?key|token)\s*[=:]\s*[\"']?([^\s\"',;]{6,64})"),
    ("bearer", r"(?i)authorization\s*[=:]\s*bearer\s+[A-Za-z0-9\-._~+/]{16,}"),
    ("conn-string", r"(?i)(server|host)=[^;]{2,};(?:database|uid|pwd|password)=[^;]{2,}"),
]


def secret_scan(text):
    """Find secrets in blob/diff content. Returns [{kind, snippet}] —
    snippets are truncated to stay operator-safe but greppable."""
    out = []
    for line in (text or "").splitlines():
        if line.startswith("+") or line.startswith("-"):
            line = line[1:]
        for kind, rx in SECRET_PATTERNS:
            m = re.search(rx, line)
            if m:
                snippet = m.group(0)
                if kind == "password-assign":
                    snippet = m.group(1) + "=" + m.group(2)[:8] + "…"
                out.append({"kind": kind, "snippet": snippet[:80]})
                break
    return out


class _ApiCaller:
    """Platform-aware API caller over the origin-bound transport."""
    def __init__(self, origin, transport, token=None, platform=None,
                 timeout=10):
        self.origin = origin
        self.transport = transport
        self.token = token
        self.platform = platform
        self.timeout = timeout
        self.context = "gitmine:" + (platform or "anon")

    def __call__(self, path, raw=False):
        if not path.startswith("/"):
            path = "/" + path
        if self.platform:
            path = PLATFORMS[self.platform]["root"] + path
        headers = {}
        if self.token and self.platform:
            style = PLATFORMS[self.platform]["auth"]
            if self.platform == "gitlab" and style == "Bearer":
                headers["PRIVATE-TOKEN"] = self.token
            else:
                headers["Authorization"] = f"{style} {self.token}"
        r = self.transport.request("GET", self.origin + path, headers=headers,
                                   context=self.context, timeout=self.timeout)
        if r.get("status", 0) != 200:
            return r.get("status"), None
        body = r.get("body", "")
        if raw:
            return 200, body
        try:
            return 200, json.loads(body)
        except ValueError:
            return 200, body


def build_api(origin, transport, token=None, platform=None, timeout=10):
    """Callable platform-aware API client over the origin-bound transport.
    `api(path)` returns (status, parsed_json_or_text)."""
    return _ApiCaller(origin, transport, token=token, platform=platform,
                      timeout=timeout)


def detect_platform(origin, transport, timeout=10):
    """Which git platform lives at this origin? Returns (name, api_root)
    or (None, None)."""
    for name, spec in PLATFORMS.items():
        api = build_api(origin, transport, platform=name, timeout=timeout)
        status, data = api(spec["probe"], raw=True)
        if status and status < 500 and data is not None:
            return name, spec["root"]
    return None, None


def parse_users(data):
    out = []
    if not isinstance(data, (list, dict)):
        return out
    items = data if isinstance(data, list) else \
        (data.get("items") or data.get("data") or [])
    for it in items:
        u = (it.get("login") or it.get("username") or it.get("name")
             or it.get("slug") or it.get("display_name") or "")
        if u:
            out.append(str(u))
    return list(dict.fromkeys(out))


def parse_repos(data):
    out = []
    items = data if isinstance(data, list) else \
        (data.get("items") or data.get("data") or [])
    for it in items:
        name = (it.get("name") or it.get("path_with_namespace")
                or it.get("full_name") or it.get("slug") or "")
        if name:
            out.append(str(name))
    return list(dict.fromkeys(out))


def _blob_pairs(platform, owner, repo, project_id=None):
    """(path template kwargs) for blob-addressed content fetch."""
    if platform == "gitlab":
        return {"p": project_id or quote(f"{owner}/{repo}", safe="")}
    if platform == "bitbucket":
        return {"ws": owner, "slug": repo}
    return {"o": quote(owner, safe=""), "r": quote(repo, safe="")}


def _decode_blob(platform, data):
    if not isinstance(data, dict):
        return ""
    field = PLATFORMS[platform]["blob_field"]
    content = data.get(field) or ""
    if data.get("encoding") == "base64" or platform in ("github", "gitlab",
                                                       "gitea"):
        try:
            return base64.b64decode(content).decode("utf-8", "ignore")
        except Exception:
            return str(content)
    return str(content)


def repo_blobs(api, platform, owner, repo, ref="master", project_id=None,
               limit=400):
    """Recursive tree of a repo — blob SHA + path per entry (hash-addressed,
    so the content fetched later cannot lie about the ref)."""
    spec = PLATFORMS[platform]
    if platform == "gitlab":
        path = spec["tree"].format(p=project_id or quote(f"{owner}/{repo}",
                                                         safe=""))
    elif platform == "bitbucket":
        path = spec["tree"].format(ws=owner, slug=repo, ref=ref)
    else:
        path = spec["tree"].format(o=quote(owner, safe=""),
                                   r=quote(repo, safe=""), ref=ref)
    status, data = api(path)
    if status != 200 or data is None:
        return []
    out = []
    items = data if isinstance(data, list) else data.get("tree") or []
    for it in items:
        if it.get("type") == "blob":
            out.append({"path": it.get("path") or it.get("name", ""),
                        "sha": it.get("sha") or ""})
    return out[:limit]


def _collect(api, path, fmt, parser, report, limit=20):
    try:
        status, data = api(path.format(n=limit, **fmt))
        if status == 200 and data is not None:
            return parser(data)
    except (KeyError, ValueError) as e:
        report["notes"].append(f"{path}: {e}")
    return []


def mine(origin, transport, token=None, deep=False, limit=30, timeout=10,
         log=None):
    """The automatic git-host sweep. Returns a full report dict; never
    raises — every per-endpoint failure is a skip with a reason."""
    log = log or (lambda m: None)
    platform, root = detect_platform(origin, transport, timeout=timeout)
    report = {"origin": origin, "platform": platform, "users": [], "orgs": [],
              "repos": [], "commits_seen": 0, "blobs_fetched": 0,
              "secrets": [], "notes": []}
    if not platform:
        report["notes"].append("no git platform detected")
        return report
    log(f"gitmine {origin}: platform={platform}")
    api = build_api(origin, transport, token=token, platform=platform,
                    timeout=timeout)
    spec = PLATFORMS[platform]
    report["users"] = _collect(api, spec["users"], {"q": ""}, parse_users,
                               report)[:20]
    report["orgs"] = _collect(api, spec["orgs"], {}, parse_users, report)[:20]
    owners = report["users"][:5] + report["orgs"][:5]
    repo_pairs = []
    for owner in owners:
        if platform == "bitbucket":
            names = _collect(api, spec["user_repos"], {"u": owner},
                             parse_repos, report)[:10]
        else:
            names = _collect(api, spec["user_repos"], {"u": owner},
                             parse_repos, report)[:10]
            names += _collect(api, spec["org_repos"], {"o": owner},
                              parse_repos, report)[:10]
        for n in names:
            if "/" in n:                       # path_with_namespace style
                o, r = n.split("/", 1)
                repo_pairs.append((o, r))
            else:
                repo_pairs.append((owner, n))
    repo_pairs = list(dict.fromkeys(repo_pairs))[:20]
    report["repos"] = [f"{o}/{r}" for o, r in repo_pairs]

    # per-repo: commit history, blob-addressed content, deleted-secret diffs
    for owner, repo in repo_pairs[:8]:
        full = f"{owner}/{repo}"
        project_id = None
        if platform == "gitlab":
            try:
                st, proj = api(f"/projects/{quote(full, safe='')}")
                project_id = proj.get("id") if st == 200 and proj else None
            except Exception:
                project_id = None
        fmt = _blob_pairs(platform, owner, repo, project_id)
        commits_path = spec["commits"].format(n=limit, **fmt)
        try:
            st, commits = api(commits_path)
            commits = commits if isinstance(commits, list) else []
        except (KeyError, ValueError):
            commits = []
        report["commits_seen"] += len(commits)
        if not deep:
            # deleted-secret diffing needs history only in deep mode
            pass
        else:
            for c in commits[:10]:
                sha = c.get("sha") or c.get("hash") or ""
                parents = c.get("parents") or []
                if not sha:
                    continue
                if parents:
                    base = parents[0].get("sha") or parents[0].get("hash") \
                        or "HEAD~1"
                    diff_path = spec["commit_diff"].format(
                        base=quote(base, safe=""), sha=quote(sha, safe=""),
                        **fmt)
                else:
                    diff_path = spec["commit_diff"].format(
                        base="", sha=quote(sha, safe=""), **fmt)
                try:
                    st, diff = api(diff_path, raw=True)
                    if st == 200 and diff:
                        for hit in secret_scan(diff):
                            if hit["snippet"].startswith("-") is False and \
                                    any(l.startswith("-") for l in
                                        str(diff).splitlines()):
                                report["secrets"].append(
                                    {"repo": full, "where": f"diff {sha[:12]}",
                                     **hit})
                except (KeyError, ValueError):
                    continue
        # blob-addressed content scan: only for small candidate files
        if spec["blob"]:
            blobs = repo_blobs(api, platform, owner, repo, project_id=project_id)
            for b in blobs[:limit]:
                sha = b.get("sha") or ""
                if not sha or not re.search(r"\.(env|conf|config|yml|yaml|json"
                                            r"|ini|key|pem|txt|sh|py)$",
                                            b.get("path", ""), re.I):
                    continue
                try:
                    st, data = api(spec["blob"].format(sha=quote(sha, safe=""),
                                                       **fmt))
                    if st != 200 or data is None:
                        continue
                    report["blobs_fetched"] += 1
                    content = _decode_blob(platform, data)
                    for hit in secret_scan(content):
                        report["secrets"].append(
                            {"repo": full, "where": f"blob {sha[:12]} "
                             f"{b.get('path', '')}", **hit})
                except (KeyError, ValueError):
                    continue
    # dedupe secrets
    seen, uniq = set(), []
    for s in report["secrets"]:
        k = (s.get("repo"), s.get("kind"), s.get("snippet"))
        if k in seen:
            continue
        seen.add(k)
        uniq.append(s)
    report["secrets"] = uniq[:50]
    log(f"gitmine {origin}: {len(report['users'])} users, "
        f"{len(report['repos'])} repos, {report['commits_seen']} commits, "
        f"{len(report['secrets'])} secret(s)")
    return report


def cli_gitmine(args):
    from .http import OriginTransport
    t = OriginTransport(timeout=args.timeout, insecure=not args.verify_tls)
    if args.resolve:
        for item in args.resolve:
            host, ip = item.split("=", 1)
            t.add_resolve(host, ip)
    report = mine(args.origin, t, token=args.token, deep=args.deep,
                  limit=args.limit, timeout=args.timeout,
                  log=lambda m: print(f"[gitmine] {m}"))
    print(json.dumps(report, indent=1, default=str))
    return 0 if report.get("platform") else 1


def build_arg_parser(sub):
    p = sub.add_parser("gitmine", help="git-host recon mine: users/orgs/"
                       "repos enumeration, commit-history diffing, deleted-"
                       "secret hunting — always via blob hashes (lesson 21)")
    p.add_argument("origin", help="git host origin, e.g. http://git.example.com")
    p.add_argument("--token", default=None, help="API token (Bearer / PRIVATE-TOKEN)")
    p.add_argument("--deep", action="store_true",
                   help="diff commit history for deleted secrets")
    p.add_argument("--limit", type=int, default=30)
    p.add_argument("--timeout", type=float, default=10)
    p.add_argument("--resolve", action="append", default=[],
                   help="host=ip override (curl --resolve semantics)")
    p.add_argument("--no-verify-tls", dest="verify_tls", action="store_false",
                   help="accept self-signed certs (lab boxes)")
    p.set_defaults(verify_tls=True, fn=cli_gitmine)
    return p
