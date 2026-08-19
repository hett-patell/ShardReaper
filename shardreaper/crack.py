#!/usr/bin/env python3
"""
crack.py — hash crackers that actually work anywhere.

Post-Cobblestone lesson 7: hashcat arrived as a pip wheel with no OpenCL and
read-only state dirs; john wasn't installed; the ad-hoc fallbacks had bugs.
These are pure-stdlib verifiers for the common Unix crypt families —
$1$ (md5crypt), $5$ (sha256crypt), $6$ (sha512crypt) — plus raw digests and a
wordlist brute with simple rules. Ground-truthed against system crypt()
vectors in tests.
"""
import hashlib
import re

_ITOA = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _to64(v, n):
    out = ""
    for _ in range(n):
        out += _ITOA[v & 0x3F]
        v >>= 6
    return out


def _b64_triple(b2, b1, b0, n):
    """sha-crypt final encoding: three digest bytes -> n base64-ish chars."""
    return _to64((b2 << 16) | (b1 << 8) | b0, n)


def _b64_from_bytes(b):
    """Encode bytes per the md5crypt 3-byte -> 4-char (little-endian) rule."""
    out = ""
    for i in range(0, len(b), 3):
        c = b[i:i + 3]
        n = c[0] << 16
        if len(c) > 1:
            n |= c[1] << 8
        if len(c) > 2:
            n |= c[2]
        out += _to64(n >> 0, 1)
        n = n >> 6
        out += _to64(n >> 0, 1)
        n = n >> 6
        out += _to64(n >> 0, 1) if len(c) > 1 else ""
        n = n >> 6
        out += _to64(n >> 0, 1) if len(c) > 2 else ""
    return out


def md5crypt(password, salt, magic="$1$"):
    """Canonical md5crypt per the PHK spec."""
    pw, sp = password.encode(), salt.encode()
    ctx = hashlib.md5(pw + magic.encode() + sp)
    alt = hashlib.md5(pw + sp + pw).digest()
    for i in range(len(pw), 0, -16):
        ctx.update(alt[:i] if i < 16 else alt[:16])
    i = len(pw)
    while i > 0:
        ctx.update(b"\x00" if i & 1 else pw[:1])
        i >>= 1
    final = ctx.digest()
    for i in range(1000):
        c = hashlib.md5()
        if i & 1:
            c.update(pw)
        else:
            c.update(final)
        if i % 3:
            c.update(sp)
        if i % 7:
            c.update(pw)
        if i & 1:
            c.update(final)
        else:
            c.update(pw)
        final = c.digest()
    # final permutation (spec table)
    out = ""
    for a, b, c in ((0, 6, 12), (1, 7, 13), (2, 8, 14), (3, 9, 15), (4, 10, 5)):
        v = final[a] << 16 | final[b] << 8 | final[c]
        out += _to64(v, 4)
    out += _to64(final[11], 2)
    return magic + salt + "$" + out


def sha_crypt(password, salt, magic="$5$", rounds=None):
    """Canonical sha256crypt/sha512crypt — verified against system crypt()."""
    use512 = magic == "$6$"
    h = hashlib.sha512 if use512 else hashlib.sha256
    P, S = password.encode(), salt.encode()
    rounds = int(rounds) if rounds else 5000
    rounds = max(1000, min(rounds, 999999999))
    digest_size = 64 if use512 else 32
    key_len = len(P)

    # 1-2: B = H(P,S,P)
    alt = h(P + S + P).digest()
    # 3: primary = H(P,S) fed with B repeated to the length of P
    primary = h(P + S)
    primary.update(alt * (key_len // digest_size))
    primary.update(alt[:(key_len % digest_size)])
    # bits of len(P): 0 -> P, 1 -> B
    bits = key_len
    while bits > 0:
        if (bits & 1) == 0:
            primary.update(P)
        else:
            primary.update(alt)
        bits >>= 1
    A = primary.digest()
    # 4-5: P' = H(P repeated len(P) times) repeated to len(P)
    t = h()
    for _ in range(key_len):
        t.update(P)
    tmp = t.digest()
    p_bytes = tmp * (key_len // digest_size) + tmp[:(key_len % digest_size)]
    # 6-7: S' = H(S repeated 16 + A[0] times) repeated to len(S)
    t2 = h()
    for _ in range(16 + A[0]):
        t2.update(S)
    tmp = t2.digest()
    s_bytes = tmp * (len(S) // digest_size) + tmp[:(len(S) % digest_size)]
    # 8: rounds loop
    for i in range(rounds):
        c = h()
        if i & 1:
            c.update(p_bytes)
        else:
            c.update(A)
        if i % 3:
            c.update(s_bytes)
        if i % 7:
            c.update(p_bytes)
        if i & 1:
            c.update(A)
        else:
            c.update(p_bytes)
        A = c.digest()
    # 9: final encoding
    out = ""
    if use512:
        table = [(0, 21, 42), (22, 43, 1), (44, 2, 23), (3, 24, 45), (25, 46, 4),
                 (47, 5, 26), (6, 27, 48), (28, 49, 7), (50, 8, 29), (9, 30, 51),
                 (31, 52, 10), (53, 11, 32), (12, 33, 54), (34, 55, 13),
                 (56, 14, 35), (15, 36, 57), (37, 58, 16), (59, 17, 38),
                 (18, 39, 60), (40, 61, 19), (62, 20, 41)]
        for a, b, c in table:
            out += _b64_triple(A[a], A[b], A[c], 4)
        out += _b64_triple(0, 0, A[63], 2)
    else:
        table = [(0, 10, 20), (21, 1, 11), (12, 22, 2), (3, 13, 23), (24, 4, 14),
                 (15, 25, 5), (6, 16, 26), (27, 7, 17), (18, 28, 8), (9, 19, 29)]
        for a, b, c in table:
            out += _b64_triple(A[a], A[b], A[c], 4)
        out += _b64_triple(0, A[31], A[30], 3)
    head = magic + S.decode()
    if rounds and rounds != 5000:
        head = f"{magic}rounds={rounds}${S.decode()}"
    return head + "$" + out


def identify(hashed):
    if hashed.startswith("$1$"):
        return "md5crypt"
    if hashed.startswith("$5$"):
        return "sha256crypt"
    if hashed.startswith("$6$"):
        return "sha512crypt"
    if re.match(r"^[0-9a-f]{32}$", hashed):
        return "raw-md5"
    if re.match(r"^[0-9a-f]{40}$", hashed):
        return "raw-sha1"
    if re.match(r"^[0-9a-f]{64}$", hashed):
        return "raw-sha256"
    return "unknown"


def verify(password, hashed):
    kind = identify(hashed)
    if kind == "raw-md5":
        return hashlib.md5(password.encode()).hexdigest() == hashed
    if kind == "raw-sha1":
        return hashlib.sha1(password.encode()).hexdigest() == hashed
    if kind == "raw-sha256":
        return hashlib.sha256(password.encode()).hexdigest() == hashed
    m = re.match(r"^\$1\$([^$]*)\$", hashed)
    if m:
        return md5crypt(password, m.group(1)) == hashed
    m = re.match(r"^\$([56])\$(?:rounds=(\d+)\$)?([^$]*)\$", hashed)
    if m:
        return sha_crypt(password, m.group(3), f"${m.group(1)}$",
                         m.group(2)) == hashed
    return False


def _rule_variants(word, rule):
    if not rule:
        return (word,)
    out = [word]
    for r in rule.split():
        for w in list(out):
            if r == "u":
                out.append(w.upper())
            elif r == "l":
                out.append(w.lower())
            elif r == "c":
                out.append(w.capitalize())
            elif r == "r":
                out.append(w[::-1])
            elif r.startswith("a") and len(r) == 2:
                out.append(w + r[1])
            elif r.startswith("^") and len(r) == 2:
                out.append(r[1] + w)
    return out


def crack(hashed, wordlist, rules=("",), log=None):
    """Wordlist brute with simple rules. Returns (password, rule) or (None, None)."""
    log = log or (lambda *a, **k: None)
    try:
        words = [w.strip() for w in open(wordlist, encoding="utf-8",
                                         errors="ignore") if w.strip()]
    except OSError as e:
        log(f"crack: cannot read wordlist: {e}")
        return None, None
    for w in words:
        for rule in rules or ("",):
            for c in _rule_variants(w, rule):
                if verify(c, hashed):
                    return c, rule or "(plain)"
    return None, None


def cli_crack(args):
    kind = identify(args.hash)
    print(f"hash type: {kind}")
    if kind in ("md5crypt", "sha256crypt", "sha512crypt", "raw-md5",
                "raw-sha1", "raw-sha256"):
        pw, rule = crack(args.hash, args.wordlist, args.rules,
                         log=lambda m: print(f"[crack] {m}"))
        if pw:
            print(f"CRACKED: {pw!r} (rule: {rule})")
            return 0
        print("not found in wordlist")
        return 1
    print("unsupported hash type (supported: $1$ $5$ $6$ raw-md5/sha1/sha256)")
    return 2


def build_arg_parser(sub):
    p = sub.add_parser("crack", help="pure-python hash cracking ($1$/$5$/$6$ + raw)")
    p.add_argument("hash", help="hash to crack")
    p.add_argument("wordlist", help="wordlist file")
    p.add_argument("--rules", action="append", default=[],
                   help="rules per candidate, e.g. 'u' 'c a1'; repeat for sets")
    p.set_defaults(fn=cli_crack)
    return p
