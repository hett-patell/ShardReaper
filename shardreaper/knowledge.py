#!/usr/bin/env python3
"""
knowledge.py — the corpus router.

ShardReaper is a knowledge-driven agent: it routes every phase to the right
technique material in the LOCAL offensive-security corpus that ships beside
it. No network needed, no LLM required — the knowledge base is the repos in
the parent tree:

    atomic-red-team                     executable ATT&CK tests (routed via atomics.py)
    hacktricks-skills                   916 SKILL.md technique skills + find_skill.py
    RedTeaming-Tactics-and-Techniques   211 ired.team deep-dive writeups
    Claude-BugHunter                    83 bug-hunting / red-team agent skills
    RedTeam-Tools                       ~150 tool/resource catalog
    Red-Teaming-Toolkit                 tool tables by phase
    Awesome-Red-Teaming                 link catalog

Search is deterministic token scoring (meta/path/body weights) — fast and
offline. Every result carries the exact path to open.
"""
import os
import re
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS_CANDIDATES = [
    ("atomic", "atomic-red-team"),
    ("hacktricks", "hacktricks-skills"),
    ("ired", "RedTeaming-Tactics-and-Techniques"),
    ("bughunter", "Claude-BugHunter"),
    ("redteam-tools", "RedTeam-Tools"),
    ("toolkit", "Red-Teaming-Toolkit"),
    ("awesome", "Awesome-Red-Teaming"),
]

_token_re = re.compile(r"[a-z0-9][a-z0-9_\-\.]+")


def tokenize(text):
    return _token_re.findall(text.lower())


def corpus_roots():
    """Locate every reference corpus beside the project (or under SHARDREAPER_CORPUS)."""
    base = os.environ.get("SHARDREAPER_CORPUS")
    if base:
        base = os.path.expanduser(base)
    else:
        base = os.path.dirname(PROJECT_ROOT)
    found = {}
    for key, name in CORPUS_CANDIDATES:
        p = os.path.join(base, name)
        if os.path.isdir(p):
            found[key] = p
    return found


def _frontmatter(text):
    if not text.startswith("---\n"):
        return "", ""
    end = text.find("\n---\n", 4)
    if end < 0:
        return "", ""
    fm = text[4:end]
    name, desc = "", ""
    for line in fm.splitlines():
        if line.lower().startswith("name:"):
            name = line.split(":", 1)[1].strip()
        elif line.lower().startswith("description:"):
            desc = line.split(":", 1)[1].strip()
    return name, desc


class _Doc:
    __slots__ = ("corpus", "rel", "path", "title", "desc", "tokens")

    def __init__(self, corpus, rel, path, title, desc, tokens):
        self.corpus = corpus
        self.rel = rel
        self.path = path
        self.title = title
        self.desc = desc
        self.tokens = tokens


def _score(doc, qtokens):
    path_toks = tokenize(doc.rel)
    meta_toks = tokenize(f"{doc.title} {doc.desc}")
    score = 0
    details = {}
    for q in qtokens:
        if q in meta_toks:
            score += 4
            details.setdefault("meta_exact", 0)
            details["meta_exact"] += 1
        elif any(q in m for m in meta_toks):
            score += 2
            details.setdefault("meta_partial", 0)
            details["meta_partial"] += 1
        if q in path_toks:
            score += 3
            details.setdefault("path_exact", 0)
            details["path_exact"] += 1
        elif any(q in p for p in path_toks):
            score += 1
            details.setdefault("path_partial", 0)
            details["path_partial"] += 1
        if q in doc.tokens:
            score += 1
            details.setdefault("body_exact", 0)
            details["body_exact"] += 1
    return score, details


class Knowledge:
    """Indexes the corpus lazily and answers queries."""

    def __init__(self, roots=None):
        self.roots = roots or corpus_roots()
        self._docs = None
        self._loaded_at = None

    @property
    def available(self):
        return sorted(self.roots.keys())

    def summary(self):
        lines = ["knowledge corpus:"]
        if not self.roots:
            lines.append("  (no reference corpora found beside the project)")
            return "\n".join(lines)
        for key in sorted(self.roots):
            n = self._count(key)
            lines.append(f"  {key:14s} {os.path.basename(self.roots[key])}  ({n} docs)")
        return "\n".join(lines)

    def _count(self, key):
        if key == "hacktricks":
            return len(self._scan_md(os.path.join(self.roots[key], "skills"), "SKILL.MD"))
        if key == "bughunter":
            return len(self._scan_md(os.path.join(self.roots[key], "skills"), "SKILL.md"))
        if key == "ired":
            base = self.roots[key]
            n = 0
            for sub in ("offensive-security", "miscellaneous-reversing-forensics", "lab"):
                n += len(self._scan_md(os.path.join(base, sub), ".md"))
            return n
        if key == "atomic":
            atomics_dir = os.path.join(self.roots[key], "atomics")
            if os.path.isdir(atomics_dir):
                return len([d for d in os.listdir(atomics_dir)
                            if os.path.isdir(os.path.join(atomics_dir, d))])
            return 0
        if key in ("redteam-tools", "toolkit", "awesome"):
            return 1
        return 0

    def _scan_md(self, root, suffix):
        out = []
        if not os.path.isdir(root):
            return out
        for dirpath, _dirs, files in os.walk(root):
            for fn in files:
                if fn.endswith(suffix):
                    out.append(os.path.join(dirpath, fn))
        return out

    def _load(self):
        if self._docs is not None:
            return self._docs
        t0 = time.time()
        docs = []
        # --- hacktricks skills (SKILL.MD) + their payload scripts ---
        if "hacktricks" in self.roots:
            base = self.roots["hacktricks"]
            for p in self._scan_md(os.path.join(base, "skills"), "SKILL.MD"):
                try:
                    text = open(p, "r", encoding="utf-8", errors="ignore").read()
                except OSError:
                    continue
                name, desc = _frontmatter(text)
                if not name:
                    name = os.path.basename(os.path.dirname(p))
                docs.append(_Doc("hacktricks", os.path.relpath(p, base), p,
                                 name, desc, set(tokenize(text[:4000]))))
            # payload scripts under skills/*/scripts (ps1/py/sh/c/go/...)
            for dirpath, _dirs, files in os.walk(os.path.join(base, "skills")):
                if not dirpath.endswith("scripts"):
                    continue
                for fn in files:
                    if not re.search(r"\.(ps1|py|sh|c|go|rs|vbs|bat|js|txt)$", fn):
                        continue
                    p = os.path.join(dirpath, fn)
                    try:
                        text = open(p, "r", encoding="utf-8", errors="ignore").read()
                    except OSError:
                        continue
                    docs.append(_Doc("hacktricks", os.path.relpath(p, base), p,
                                     f"payload: {fn}", "", set(tokenize(text[:2000]))))
        # --- ired.team writeups + reversing/forensics + lab infrastructure ---
        if "ired" in self.roots:
            base = self.roots["ired"]
            for sub in ("offensive-security", "miscellaneous-reversing-forensics", "lab"):
                for p in self._scan_md(os.path.join(base, sub), ".md"):
                    try:
                        text = open(p, "r", encoding="utf-8", errors="ignore").read()
                    except OSError:
                        continue
                    title = os.path.basename(p)[:-3].replace("-", " ").title()
                    docs.append(_Doc("ired", os.path.relpath(p, base), p, title, "",
                                     set(tokenize(text[:2500]))))
            # lab configs (sysmon/logstash/interfaces) are non-md but still indexed
            for p in self._scan_md(os.path.join(base, "lab"), ".xml") + \
                    self._scan_md(os.path.join(base, "lab"), ".conf") + \
                    self._scan_md(os.path.join(base, "lab"), ".yml"):
                docs.append(_Doc("ired", os.path.relpath(p, base), p,
                                 f"lab: {os.path.basename(p)}", "",
                                 set(tokenize(open(p, errors="ignore").read()[:1500]))))
        # --- bughunter skills ---
        if "bughunter" in self.roots:
            base = self.roots["bughunter"]
            for p in self._scan_md(os.path.join(base, "skills"), "SKILL.md"):
                try:
                    text = open(p, "r", encoding="utf-8", errors="ignore").read()
                except OSError:
                    continue
                name, desc = _frontmatter(text)
                if not name:
                    name = os.path.basename(os.path.dirname(p))
                docs.append(_Doc("bughunter", os.path.relpath(p, base), p,
                                 name, desc, set(tokenize(text[:3000]))))
        self._docs = docs
        self._loaded_at = time.time()
        return docs

    def search(self, query, limit=8, corpora=None):
        """Ranked search across the corpus. Returns list of dicts."""
        qtokens = tokenize(query)
        if not qtokens:
            return []
        docs = self._load()
        scored = []
        for d in docs:
            if corpora and d.corpus not in corpora:
                continue
            s, details = _score(d, qtokens)
            if s > 0:
                scored.append((s, details, d))
        scored.sort(key=lambda x: (-x[0], x[2].corpus, x[2].rel))
        out = []
        for s, details, d in scored[:limit]:
            out.append({
                "score": s,
                "corpus": d.corpus,
                "title": d.title,
                "path": d.path,
                "rel": d.rel,
                "desc": d.desc[:220],
                "evidence": details,
            })
        return out

    def search_technique(self, phase_keywords, limit=6):
        """Convenience: query the corpus for the current ATT&CK phase."""
        return self.search(" ".join(phase_keywords), limit=limit)

    def find_hacktricks(self, query, top=8):
        """Prefer the shipped find_skill.py when present (it knows the corpus best)."""
        script = os.path.join(self.roots.get("hacktricks", ""),
                              "skills-locator-navigation", "scripts", "find_skill.py")
        if os.path.isfile(script):
            import subprocess
            try:
                p = subprocess.run(
                    ["python3", script, "--skills-root",
                     os.path.join(self.roots["hacktricks"], "skills"),
                     "--query", query, "--top", str(top)],
                    capture_output=True, text=True, timeout=60)
                lines = [l for l in p.stdout.splitlines() if l.strip() and "score=" in l]
                if lines:
                    return lines[:top]
            except Exception:
                pass
        return [r["path"] for r in self.search(query, limit=top, corpora=["hacktricks"])]

    def open_best(self, query, corpus=None):
        """Return the path of the single best doc for a query, or None."""
        rs = self.search(query, limit=1, corpora=[corpus] if corpus else None)
        return rs[0]["path"] if rs else None


def cli_search(query, limit=8, corpus=None):
    k = Knowledge()
    results = k.search(query, limit=limit, corpora=[corpus] if corpus else None)
    if not results:
        print(f"no hits for: {query}")
        return
    print(f"top {len(results)} hits for: {query}")
    print("-" * 72)
    for r in results:
        print(f"[{r['score']:3d}] {r['corpus']:12s} {r['title']}")
        print(f"      {r['rel']}")
        if r["desc"]:
            print(f"      {r['desc']}")
    print()
    print("open with: shardreaper kb-open <query>   |   full path above")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="ShardReaper knowledge base")
    ap.add_argument("query", nargs="*")
    ap.add_argument("--limit", type=int, default=8)
    ap.add_argument("--corpus")
    args = ap.parse_args()
    if args.query:
        cli_search(" ".join(args.query), args.limit, args.corpus)
    else:
        print(Knowledge().summary())
