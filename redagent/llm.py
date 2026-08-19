#!/usr/bin/env python3
"""
llm.py — the optional brain.

When REDAGENT_LLM_BASE / REDAGENT_LLM_KEY / REDAGENT_LLM_MODEL are set, the
engine dispatches decision tasks to an OpenAI-compatible chat endpoint
(OpenAI, DeepSeek, local vLLM/Ollama, ...). Without a key the engine runs in
deterministic mode: same phases, same gates, knowledge-driven decisions.

The persona (persona.py) is always injected. Scope rules are always injected.
The model decides tactics; the code decides whether an action may run.
"""
import json
import os
import re
import time

try:
    import requests as _requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

BASE = os.environ.get("REDAGENT_LLM_BASE", "https://api.openai.com/v1")
KEY = os.environ.get("REDAGENT_LLM_KEY", "")
MODEL = os.environ.get("REDAGENT_LLM_MODEL", "gpt-4o-mini")
TIMEOUT = int(os.environ.get("REDAGENT_LLM_TIMEOUT", "120"))


def available():
    return bool(KEY)


def _post(url, payload):
    if HAVE_REQUESTS:
        r = _requests.post(url, json=payload, timeout=TIMEOUT,
                           headers={"Authorization": f"Bearer {KEY}"})
        r.raise_for_status()
        return r.json()
    import urllib.request
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Authorization": f"Bearer {KEY}",
                                          "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read().decode())


def chat(messages, max_tokens=1200, temperature=0.4, model=None):
    payload = {"model": model or MODEL, "messages": messages,
               "max_tokens": max_tokens, "temperature": temperature}
    data = _post(f"{BASE.rstrip('/')}/chat/completions", payload)
    try:
        return data["choices"][0]["message"]["content"] or ""
    except (KeyError, IndexError):
        return ""


def extract_json(text):
    """Pull the last valid JSON object/array out of a model reply."""
    if not text:
        return None
    blocks = re.findall(r"```json\s*(.*?)```", text, re.S)
    blocks += re.findall(r"```\s*(\[.*?\]|\{.*?\})\s*```", text, re.S)
    for b in reversed(blocks):
        try:
            return json.loads(b.strip())
        except Exception:
            pass
    for b in reversed(re.findall(r"(\{.*\}|\[.*\])", text, re.S)):
        try:
            return json.loads(b)
        except Exception:
            pass
    return None


def decide(task, system=None, context=None, want_json=True, max_tokens=1200):
    """One decision dispatch. Returns (text, json_or_None)."""
    if not available():
        return None, None
    msgs = []
    if system:
        msgs.append({"role": "system", "content": system})
    prompt = task
    if context:
        prompt += "\n\n## CONTEXT\n" + json.dumps(context, indent=1, default=str)[:6000]
    if want_json:
        prompt += ("\n\nRespond with a fenced ```json``` block containing your structured "
                   "answer. Keep any prose short.")
    msgs.append({"role": "user", "content": prompt})
    try:
        text = chat(msgs, max_tokens=max_tokens)
    except Exception as e:
        return None, {"error": f"llm:{e}"}
    return text, extract_json(text)


def cli_ask(args):
    cli_ask_question(" ".join(args.task), args.scope, args.objective, args.max_tokens)


def cli_ask_question(task, scope, objective, max_tokens):
    if not available():
        print("no brain configured: set REDAGENT_LLM_BASE/REDAGENT_LLM_KEY/"
              "REDAGENT_LLM_MODEL (OpenAI-compatible). Deterministic mode active.")
        return
    from .persona import build_operator_prompt
    sys = build_operator_prompt(scope or "", objective or "", llm_tools=False)
    text, js = decide(task, system=sys, want_json=False, max_tokens=max_tokens)
    print(text or "(empty reply)")


def build_arg_parser(sub):
    p = sub.add_parser("ask", help="ask the LLM brain a question (needs REDAGENT_LLM_*)")
    p.add_argument("task", nargs="+", help="question for the brain")
    p.add_argument("--scope", default="")
    p.add_argument("--objective", default="")
    p.add_argument("--max-tokens", type=int, default=1200)
    p.set_defaults(fn=cli_ask)
    return p
