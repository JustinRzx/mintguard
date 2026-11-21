#!/usr/bin/env python3
"""MintGuard — a read-only BSC mint risk-screening agent.

Wraps the BSC Mint Precheck engine (engine/bsc_mint_precheck.py) as a small
public HTTPS API. The engine contains NO signing, approval or payment code
path: it only reads chain state, fetches public metadata and simulates
candidate mint calls with eth_call at value 0. This service adds nothing
that can move funds either — it validates input, rate-limits, runs the
engine as a subprocess, and returns its JSON verdict.

Endpoints:
  GET  /            info + live demo page
  GET  /health      {"status": "ok", ...}
  GET  /check?input=<url-or-0xaddress>&wallet=<0x optional>
  POST /check       {"input": "...", "wallet": "0x... (optional)"}
"""

import json
import os
import re
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.join(HERE, "engine", "scripts", "bsc_mint_precheck.py")
PORT = int(os.environ.get("MINTGUARD_PORT", "8734"))
REPO_URL = os.environ.get("MINTGUARD_REPO_URL", "")
ENGINE_TIMEOUT = 120  # seconds; a deep scan reads many chain getters in parallel

ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
URL_RE = re.compile(r"^https?://\S{1,480}$")

_sem = threading.Semaphore(2)          # at most 2 concurrent scans
_last_by_ip = {}                        # naive per-IP pacing
_lock = threading.Lock()

PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MintGuard — BSC Mint Risk Screener</title>
<style>
body{font-family:system-ui,sans-serif;background:#0b0e14;color:#e6e9ef;margin:0;padding:24px;max-width:820px;margin-inline:auto}
h1{font-size:28px;margin-bottom:4px} .tag{color:#8b93a5}
.card{background:#131824;border:1px solid #232a3a;border-radius:12px;padding:16px;margin:16px 0}
code{background:#1b2233;padding:2px 6px;border-radius:6px}
input{width:100%;padding:10px;border-radius:8px;border:1px solid #2a3348;background:#0b0e14;color:#e6e9ef;box-sizing:border-box}
button{margin-top:10px;padding:10px 18px;border:0;border-radius:8px;background:#3b82f6;color:#fff;cursor:pointer}
pre{white-space:pre-wrap;word-break:break-word;background:#0b0e14;border:1px solid #232a3a;border-radius:8px;padding:12px;max-height:420px;overflow:auto}
.warn{color:#fbbf24}.ok{color:#34d399}.bad{color:#f87171}
a{color:#60a5fa}
</style></head><body>
<h1>🛡️ MintGuard</h1>
<div class="tag">A read-only screening agent for BSC mints, claims and fair sales — built for the
Binance Agent ID ecosystem. It answers one question before any wallet signs anything:
<em>is this mint what it claims to be, and is it safe to touch?</em></div>

<div class="card"><strong>Try it live</strong>
<p>Paste a BSC contract address (0x…) or a mint page URL. A full scan reads live chain
state and can take 10–60 seconds.</p>
<input id="inp" placeholder="0x… or https://project.example/mint">
<button onclick="run()">Run precheck</button>
<pre id="out">Verdict will appear here.</pre></div>

<div class="card"><strong>What it checks</strong>
<ul>
<li>Identifies the real mint contract behind a page or address (code, codehash, EIP-1967 proxy slots).</li>
<li>Reads price, quota, supply, pause and open flags live from the chain — never from the project's own claims.</li>
<li>Detects the Agent ID gate and verifies it against the real SPACE ID registry (0x60B9…022F).</li>
<li>Simulates the mint call with <code>eth_call</code> at value 0 and records the outcome or revert reason.</li>
<li>Fingerprints the contract (mint selectors + proxy type + gate traits) and matches it against an
experience database of past mints, so a redeploy of a known family is recognised on sight.</li>
<li>Returns a structured verdict (e.g. CANDIDATE_FREE, PAID, CLOSED_OR_SOLDOUT) plus plain-language warnings.</li>
</ul>
<p><strong>Read-only by construction:</strong> the engine contains no signing, approval or payment
code path at all. MintGuard can look, but it cannot touch funds.</p></div>

<div class="card"><strong>API</strong>
<p><code>GET /check?input=&lt;url-or-address&gt;&amp;wallet=&lt;optional 0x&gt;</code> or
<code>POST /check</code> with JSON <code>{"input": "…"}</code>. Response: a compact summary
(verdict, warnings, gate, history match) plus the full engine report under <code>report</code>.
Health: <code>GET /health</code>.</p>
<p>Built for the zkVerify Agent Games — Wildcard track. __REPO__</p></div>
<script>
async function run(){
  const v=document.getElementById('inp').value.trim();
  const out=document.getElementById('out');
  if(!v){out.textContent='Paste an address or URL first.';return}
  out.textContent='Scanning live chain state…';
  try{
    const r=await fetch('/check?input='+encodeURIComponent(v));
    const d=await r.json();
    if(d.error){out.textContent='Error: '+d.error;return}
    let lines=['VERDICT: '+d.verdict,'Address: '+d.address];
    if(d.history_match){lines.push('Known family: '+JSON.stringify(d.history_match))}
    if(d.warnings&&d.warnings.length){lines.push('','Warnings:');d.warnings.forEach(w=>lines.push('  ⚠ '+w))}
    lines.push('','Full report included in the JSON response of /check.');
    out.textContent=lines.join('\\n');
  }catch(e){out.textContent='Request failed: '+e}
}
</script></body></html>"""


def run_precheck(inp, wallet):
    cmd = [sys.executable, ENGINE, "precheck", inp]
    if wallet:
        cmd += ["--wallet", wallet]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=ENGINE_TIMEOUT, cwd=HERE)
    except subprocess.TimeoutExpired:
        return None, "engine timed out after %ds" % ENGINE_TIMEOUT
    if p.returncode != 0:
        return None, "engine failed: " + (p.stderr or p.stdout or "")[-300:]
    try:
        return json.loads(p.stdout), None
    except Exception:
        return None, "engine returned unparseable output"


def summarize(report):
    v = report.get("verdict") or {}
    hm = report.get("history_match") or {}
    hm_out = None
    if hm:
        hm_out = {k: hm.get(k) for k in ("pattern_name", "score", "method")
                  if hm.get(k) is not None} or hm
    gate = report.get("gate") or {}
    gate_out = {k: gate.get(k) for k in
                ("is_agent_id_gated", "registry_match", "gate_type")
                if k in gate} or None
    return {
        "agent": "MintGuard",
        "version": "1.0.0",
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "input": report.get("input"),
        "address": report.get("address"),
        "verdict": v.get("verdict"),
        "verdict_detail": v,
        "warnings": report.get("warnings") or [],
        "history_match": hm_out,
        "gate": gate_out,
        "report": report,
    }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stdout.write("%s %s\n" % (self.address_string(), fmt % args))
        sys.stdout.flush()

    def _json(self, code, obj):
        body = json.dumps(obj, indent=1).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _pace(self):
        ip = self.address_string()
        now = time.time()
        with _lock:
            last = _last_by_ip.get(ip, 0)
            if now - last < 3:
                return False
            _last_by_ip[ip] = now
        return True

    def _check(self, inp, wallet):
        if not inp or not (ADDR_RE.match(inp) or URL_RE.match(inp)):
            return self._json(400, {"error": "input must be a 0x address or an http(s) URL"})
        if wallet and not ADDR_RE.match(wallet):
            return self._json(400, {"error": "wallet must be a 0x address"})
        if not self._pace():
            return self._json(429, {"error": "slow down: one scan per IP per 3 seconds"})
        if not _sem.acquire(blocking=False):
            return self._json(429, {"error": "busy: two scans already running, retry shortly"})
        try:
            report, err = run_precheck(inp, wallet)
        finally:
            _sem.release()
        if err:
            return self._json(502, {"error": err})
        return self._json(200, summarize(report))

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/health":
            return self._json(200, {"status": "ok", "agent": "MintGuard",
                                    "version": "1.0.0", "engine": "bsc_mint_precheck"})
        if u.path == "/check":
            q = parse_qs(u.query)
            return self._check((q.get("input") or [""])[0].strip(),
                               (q.get("wallet") or [""])[0].strip() or None)
        if u.path == "/":
            repo = ('<a href="%s">Source repository</a>.' % REPO_URL) if REPO_URL else ""
            body = PAGE.replace("__REPO__", repo).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            return self.wfile.write(body)
        return self._json(404, {"error": "not found"})

    def do_POST(self):
        u = urlparse(self.path)
        if u.path != "/check":
            return self._json(404, {"error": "not found"})
        try:
            n = int(self.headers.get("Content-Length") or 0)
            data = json.loads(self.rfile.read(min(n, 65536)) or b"{}")
        except Exception:
            return self._json(400, {"error": "body must be JSON"})
        return self._check(str(data.get("input") or "").strip(),
                           str(data.get("wallet") or "").strip() or None)


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print("MintGuard listening on 127.0.0.1:%d" % PORT, flush=True)
    srv.serve_forever()
