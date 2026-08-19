#!/usr/bin/env python3
"""
fuzz.py — surface discovery through whatever read primitive you hold.

Post-Cobblestone lesson 2: LOAD_FILE reads files, but nothing enumerated
directories, so the mid-game surface stayed invisible. Two fixes here:

  * harvest_refs — derive candidate file lists from rendered pages and
    template includes (include/require/href/src/action).
  * fuzz_paths  — feed every candidate through a read-check callable
    (a working SQLi file read, an LFI, a fetch) and keep what answers.

The operator supplies the working exfil one-liner; fuzz feeds it names.
"""
import os
import re
import subprocess

WEB_WORDLIST = [
    "index.php", "config.php", "config.inc.php", "db.php", "database.php",
    "admin.php", "admin/index.php", "login.php", "logout.php", "setup.php",
    "install.php", "skins.php", "template.php", "header.php", "footer.php",
    "preview.php", "preview_banner.php", "banner.php", "upload.php", "files.php",
    "includes.php", "functions.php", "utils.php", "helpers.php", "settings.php",
    ".htaccess", ".git/config", ".env", "robots.txt", "composer.json",
    "package.json", "app.py", "main.py", "utils.py", "views.py", "models.py",
    "requirements.txt", "wsgi.py", "manage.py", "Dockerfile", "docker-compose.yml",
    "web.config", "phpinfo.php", "info.php", "cron.php", "api.php", "ajax.php",
    "vote.php", "suggest.php", "submit.php", "search.php", "profile.php",
    "user.php", "users.php", "auth.php", "session.php", "flag.txt", "flag",
    "secret.txt", "id_rsa", "backup.sql", "dump.sql", "database.sql",
]

_REF_RE = re.compile(
    r"(?:include|require(?:_once)?|href|src|action|url)\s*[=(:\"]\s*['\"]?"
    r"([a-zA-Z0-9_./\-]+\.(?:php|py|js|html?|css|txt|inc|tpl))", re.I)


def harvest_refs(html):
    """Candidate file list derived from a rendered page / template dump."""
    found = set()
    for m in _REF_RE.finditer(html or ""):
        p = m.group(1).lstrip("./")
        if "/" not in p or p.startswith(("http", "//")):
            continue
        found.add(p)
    return sorted(found)


def fuzz_paths(read_check, candidates=None, base_dir="", log=None, stop_after=None):
    """Feed candidates through read_check(candidate) — keep the ones that answer.

    read_check returns a truthy value (content) or None/"" for a miss.
    """
    log = log or (lambda *a, **k: None)
    words = list(candidates) if candidates else list(WEB_WORDLIST)
    found = []
    for w in words:
        cand = w if w.startswith("/") else base_dir.rstrip("/") + "/" + w
        try:
            content = read_check(cand)
        except Exception as e:
            log(f"fuzz: {cand} — read-check error {e}")
            continue
        if content:
            found.append({"path": cand, "size": len(content or ""),
                          "head": (content or "")[:80]})
            log(f"fuzz: HIT {cand} ({len(content or '')} bytes)")
        if stop_after and len(found) >= stop_after:
            break
    return found


def cli_fuzz(args):
    # the read primitive: a shell command template with {p} as the candidate
    hits = []
    words = list(WEB_WORDLIST)
    if args.wordlist and os.path.isfile(args.wordlist):
        words = [ln.strip() for ln in open(args.wordlist, encoding="utf-8",
                                           errors="ignore") if ln.strip()]
    if args.refs:
        for src in args.refs:
            try:
                words += harvest_refs(open(src, encoding="utf-8",
                                           errors="ignore").read())
            except OSError as e:
                print(f"cannot read refs {src}: {e}")
        words = list(dict.fromkeys(words))

    def check(cand):
        cmd = args.read_cmd.replace("{p}", cand)
        try:
            p = subprocess.run(["sh", "-c", cmd], capture_output=True,
                               text=True, timeout=args.timeout)
            out = p.stdout.strip()
            return out if out and p.returncode == 0 else None
        except (subprocess.TimeoutExpired, OSError):
            return None

    hits = fuzz_paths(check, words, args.base, log=lambda m: print(f"[fuzz] {m}"))
    print(f"\n{len(hits)} hit(s) from {len(words)} candidate(s):")
    for h in hits:
        print(f"  {h['path']} ({h['size']} bytes) :: {h['head']}")
    if args.output:
        import json
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(hits, f, indent=1)
        print(f"report written: {args.output}")
    return 0


def build_arg_parser(sub):
    p = sub.add_parser("fuzz", help="discover files/dirs through any read primitive "
                        "(post-Cobblestone lesson 2)")
    p.add_argument("--read-cmd", required=True,
                   help="shell one-liner that outputs file content; {p} = candidate "
                        "path, e.g. 'curl -s \"http://tgt/view?f={p}\"'")
    p.add_argument("--base", default="", help="base dir/URL prefix for candidates")
    p.add_argument("--wordlist", default=None)
    p.add_argument("--refs", action="append", default=[],
                   help="rendered page/template dump to harvest refs from (repeat)")
    p.add_argument("--timeout", type=int, default=10)
    p.add_argument("--output", default=None)
    p.set_defaults(fn=cli_fuzz)
    return p
