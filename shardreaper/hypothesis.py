#!/usr/bin/env python3
"""
hypothesis.py — hypothesis lifecycle: budgets, kill-criteria, tombstones
(lesson 19).

The old failure: theories ran until the operator manually stopped them.
Dead theories got resurrected at the cost of the engagement's most scarce
resource — the next pivot.

Invariants, enforced here:

* EVERY theory carries a probe budget and a no-evidence cutoff.
* Every probe result either adds evidence (which resets the no-evidence
  counter) or spends budget and advances the cutoff counter.
* A theory that exhausts its budget or hits the no-evidence cutoff is
  KILLED with a recorded reason — a tombstone in cross-engagement memory.
* A tombstoned theory is never resurrected: the plan/attack phases refuse
  to run it, and the refusal cites the recorded reason.
"""
import os


def new_hypothesis(eng, theory, host=None, budget=3, cutoff=3, detail=""):
    """Create (or reuse) a tracked theory. Returns the record."""
    hid = f"H{len(eng.state.setdefault('hypotheses', [])) + 1:03d}"
    rec = {"id": hid, "theory": theory, "host": host, "detail": detail[:200],
           "budget": int(budget), "cutoff": int(cutoff),
           "probes": 0, "no_evidence": 0, "evidence": [],
           "status": "running", "tombstone": None}
    eng.state["hypotheses"].append(rec)
    eng.save()
    return rec


def get(eng, hid):
    for h in eng.state.get("hypotheses", []):
        if h.get("id") == hid:
            return h
    return None


def note_evidence(eng, hid, evidence):
    """Evidence RESETS the no-evidence counter — the theory earned more runway."""
    h = get(eng, hid)
    if not h or h.get("status") != "running":
        return h
    h["evidence"].append(str(evidence)[:300])
    h["no_evidence"] = 0
    eng.save()
    return h


def probe_failed(eng, hid, note=""):
    """One probe without evidence. Spends budget, advances the cutoff
    counter, and KILLS the theory when either runs out."""
    h = get(eng, hid)
    if not h or h.get("status") != "running":
        return h
    h["probes"] += 1
    h["no_evidence"] += 1
    if note:
        h.setdefault("last_note", []).append(str(note)[:160])
    if h["no_evidence"] >= h["cutoff"]:
        return kill(eng, hid, f"no-evidence cutoff reached: "
                    f"{h['cutoff']} consecutive probes without evidence")
    if h["probes"] >= h["budget"]:
        return kill(eng, hid, f"budget exhausted: {h['budget']} probes with "
                    f"{len(h['evidence'])} evidence event(s)")
    eng.save()
    return h


def kill(eng, hid, reason):
    """Kill the theory and tombstone it in cross-engagement memory so it is
    NEVER resurrected."""
    h = get(eng, hid)
    if not h:
        return None
    h["status"] = "dead"
    h["tombstone"] = reason[:300]
    eng.save()
    try:
        from . import memory
        memory.log_tombstone(h.get("host"), h.get("theory"), reason)
    except Exception:
        pass
    return h


def tombstoned(host, theory):
    """Is this theory already dead for this host? Returns the reason or None."""
    try:
        from . import memory
        return memory.tombstoned(host, theory)
    except Exception:
        return None


def summarize(eng):
    lines = [f"hypotheses: {len(eng.state.get('hypotheses', []))}"]
    for h in eng.state.get("hypotheses", []):
        tag = {"running": "RUN", "dead": "DEAD"}.get(h["status"], h["status"])
        lines.append(f"  [{tag}] {h['id']} {h['theory'][:60]} "
                     f"probes={h['probes']}/{h['budget']} "
                     f"evidence={len(h['evidence'])}"
                     + (f" — {h['tombstone']}" if h["tombstone"] else ""))
    return "\n".join(lines)


def cli_hypotheses(args):
    from .state import Engagement
    base = os.path.abspath(args.dir)
    if not os.path.isfile(os.path.join(base, "state.json")):
        print(f"no engagement at {base}")
        return 1
    print(summarize(Engagement.load(base)))
    return 0


def build_arg_parser(sub):
    p = sub.add_parser("hypotheses", help="hypothesis lifecycle ledger: "
                       "budgets, no-evidence cutoffs, tombstones (lesson 19)")
    p.add_argument("dir", help="engagement folder")
    p.set_defaults(fn=cli_hypotheses)
    return p
