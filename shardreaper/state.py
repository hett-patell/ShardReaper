#!/usr/bin/env python3
"""
state.py — engagement state & audit ledger.

Every action the agent takes is appended to a JSONL ledger inside the
engagement folder. State is persisted after every step: a run is resumable
and fully auditable. The operator can replay exactly what the agent did.
"""
import json
import os
import time
from datetime import datetime, timezone

# ATT&CK-style phase order the engine walks
PHASES = [
    "engage", "recon", "analyze", "plan", "attack",
    "escalate", "persist", "move", "harvest", "spray",
    "evade", "exfil", "report",
]


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Engagement:
    def __init__(self, base, name="engagement", scope_path=None, created=None):
        self.base = base
        self.ledger_path = os.path.join(base, "ledger.jsonl")
        self.state_path = os.path.join(base, "state.json")
        self.name = name
        self.scope_path = scope_path
        self.created = created or now_iso()
        self.phase = "engage"
        self.state = {
            "name": name,
            "created": self.created,
            "updated": self.created,
            "scope_path": scope_path,
            "phase": "engage",
            "seeds": [],
            "targets": [],          # discovered live hosts
            "findings": [],         # confirmed findings
            "credentials": [],      # harvested credentials (token spray feed)
            "intel": {},            # per-host intel
            "plan": [],             # attack plan items
            "actions": [],          # executed techniques
            "notes": [],
        }
        os.makedirs(base, exist_ok=True)

    # ---------------- persistence ----------------
    def save(self):
        self.state["updated"] = now_iso()
        self.state["phase"] = self.phase
        with open(self.state_path, "w", encoding="utf-8") as f:
            json.dump(self.state, f, indent=2)

    def log(self, msg, level="info"):
        entry = {"ts": now_iso(), "level": level, "phase": self.phase, "msg": msg}
        with open(self.ledger_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        tag = {"info": " .", "warn": "!!", "err": "XX", "action": ">>", "win": "++"}.get(level, " .")
        print(f"[{self.phase:9s}]{tag} {msg}", flush=True)

    def log_action(self, technique, target, detail, outcome="ran", evidence=None, result=None):
        rec = {
            "ts": now_iso(), "phase": self.phase, "technique": technique,
            "target": target, "detail": detail, "outcome": outcome,
            "evidence": evidence or [], "result": result,
        }
        self.state["actions"].append(rec)
        self.save()
        return rec

    def add_finding(self, title, severity, class_, technique, target, evidence, detail,
                    impact="", remediation=""):
        fid = f"F{len(self.state['findings']) + 1:03d}"
        finding = {
            "id": fid, "title": title, "severity": severity, "class": class_,
            "technique": technique, "target": target, "evidence": evidence,
            "detail": detail, "impact": impact, "remediation": remediation,
            "ts": now_iso(),
        }
        self.state["findings"].append(finding)
        self.save()
        self.log(f"{fid} {severity.upper()} {title} @ {target}", level="win")
        try:  # cross-engagement memory capture — never breaks the run
            from . import memory
            memory.log_finding(self.state.get("name", "engagement"), target, finding)
        except Exception:
            pass
        return finding

    def set_phase(self, phase):
        self.phase = phase
        self.state["phase"] = phase
        self.save()

    def add_credential(self, type_, value, user=None, source=None, note=None):
        """Add a harvested credential to the spray feed. Deduplicated by
        (type, value) — the spray phase auto-fires the whole set against
        every authenticated surface."""
        if not value:
            return None
        for c in self.state.setdefault("credentials", []):
            if c.get("type") == type_ and c.get("value") == value:
                return c
        cred = {"type": type_, "value": value, "user": user,
                "source": source, "note": note, "ts": now_iso()}
        self.state["credentials"].append(cred)
        self.save()
        self.log(f"credential held: {type_} ({source or 'operator'})", level="action")
        return cred

    # ---------------- loading ----------------
    @classmethod
    def load(cls, base):
        with open(os.path.join(base, "state.json"), "r", encoding="utf-8") as f:
            st = json.load(f)
        eng = cls(base, st.get("name", "engagement"), st.get("scope_path"),
                  created=st.get("created"))
        eng.phase = st.get("phase", "engage")
        eng.state = st
        return eng

    def add_target(self, host, url=None, status=None, tech=None, ports=None):
        for t in self.state["targets"]:
            if t["host"] == host:
                if url:
                    t.setdefault("url", url)
                if status:
                    t["status"] = status
                if tech:
                    t["tech"] = sorted(set(t.get("tech", []) + tech))
                if ports:
                    t["ports"] = sorted(set(t.get("ports", []) + ports))
                self.save()
                return t
        t = {"host": host, "url": url, "status": status, "tech": tech or [],
             "ports": ports or [], "intel": {}}
        self.state["targets"].append(t)
        self.save()
        return t
