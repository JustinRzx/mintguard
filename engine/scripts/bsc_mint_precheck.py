#!/usr/bin/env python3
"""BSC Mint Precheck engine.

Read-only by design: this script contains NO signing, approval or payment
code path. It only reads chain state (eth_call, eth_getCode, storage slots),
fetches public metadata (Sourcify, project pages) and simulates candidate
mint calls with eth_call at value 0.

Usage:
  bsc_mint_precheck.py self-test
  bsc_mint_precheck.py init-db
  bsc_mint_precheck.py precheck <URL-or-0xAddress> [--wallet 0x...] [--human] [--out report.json]
  bsc_mint_precheck.py history [--limit 10]
  bsc_mint_precheck.py learn --pattern-id ID --name NAME --outcome succeeded|failed|mixed|blocked \
      --method "..." --failures "reason one; reason two" --signatures "mint(uint256)" --traits "challenge"
"""
import argparse
import hashlib
import json
import os
import re
import sqlite3
import sys
import threading
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor

# --------------------------------------------------------------------------
# Pure-python Keccak-256 (Keccak padding, not SHA3)
# --------------------------------------------------------------------------
_MASK64 = (1 << 64) - 1
_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_KECCAK_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]


def _rotl64(x, n):
    if n == 0:
        return x & _MASK64
    return ((x << n) | (x >> (64 - n))) & _MASK64


def _keccak_f1600(state):
    for rc in _KECCAK_RC:
        # theta
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        d = [c[(x + 4) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        # rho + pi
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl64(state[x + 5 * y], _KECCAK_ROT[x][y])
        # chi
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
        # iota
        state[0] ^= rc


def keccak256(data: bytes) -> bytes:
    rate = 136  # 1088-bit rate for 256-bit output
    state = [0] * 25
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != rate - 1:
        padded.append(0x00)
    padded.append(0x80)
    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(block[i * 8:(i + 1) * 8], "little")
            state[i] ^= lane
        _keccak_f1600(state)
    out = bytearray()
    for i in range(4):
        out += state[i].to_bytes(8, "little")
    return bytes(out[:32])


def selector(signature: str) -> str:
    return "0x" + keccak256(signature.encode()).hex()[:8]


# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------
SPACE_ID_REGISTRY = "0x60b9262456de011f7d15a54cdd8c48baaa8b022f"
DEFAULT_RPCS = [
    "https://bsc-dataseed.bnbchain.org",
    "https://bsc-dataseed1.defibit.io",
    "https://bsc-dataseed.binance.org",
    "https://bsc-dataseed2.bnbchain.org",
    "https://rpc-bsc.48.club",
]
EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
EIP1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(SKILL_DIR, "data", "experience.sqlite3")
SEED_PATH = os.path.join(SKILL_DIR, "scripts", "experience_seed.json")
KNOWN_ERRORS = {
    "0xf402e5b1": "DailyLimitReached",
    "0xd9c1988f": "InvalidSolution",
    "0xc9838a65": "ProofAlreadyUsed",
    "0x178423dd": "InvalidIdentity",
    "0xefdc789e": "MiningNotStarted",
    "0x7862e959": "InvalidBatchSize",
    "0x8a7d2016": "MiningFinished",
    "0x577742ca": "RewardChanged",
    "0xe82a5329": "InvalidStage",
    "0x15aed598": "GratisSoldOut (project-specific, seen on YYDS)",
}

# --------------------------------------------------------------------------
# JSON-RPC client (rotates endpoints, stdlib only)
# --------------------------------------------------------------------------
_rpc_lock = threading.Lock()
_rpc_counter = [0]


def rpc(method, params, timeout=20):
    with _rpc_lock:
        start = _rpc_counter[0] % len(DEFAULT_RPCS)
        _rpc_counter[0] += 1
    last_err = None
    for i in range(len(DEFAULT_RPCS)):
        url = DEFAULT_RPCS[(start + i) % len(DEFAULT_RPCS)]
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
        req = urllib.request.Request(url, data=body, headers={"content-type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = json.loads(resp.read().decode())
            if "error" in payload:
                last_err = payload["error"]
                continue
            return payload.get("result")
        except Exception as exc:  # network, timeout, bad json
            last_err = str(exc)
            continue
    raise RuntimeError(f"RPC {method} failed on all endpoints: {last_err}")


def eth_call(to, data, from_addr=None, value=0):
    """Return (True, hexdata) or (False, error-dict-or-str)."""
    tx = {"to": to, "data": data, "value": hex(value)}
    if from_addr:
        tx["from"] = from_addr
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_call", "params": [tx, "latest"]}).encode()
    with _rpc_lock:
        start = _rpc_counter[0] % len(DEFAULT_RPCS)
        _rpc_counter[0] += 1
    last_err = None
    for i in range(len(DEFAULT_RPCS)):
        url = DEFAULT_RPCS[(start + i) % len(DEFAULT_RPCS)]
        req = urllib.request.Request(url, data=body, headers={"content-type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                payload = json.loads(resp.read().decode())
            if "error" in payload:
                return False, payload["error"]
            return True, payload.get("result", "0x")
        except Exception as exc:
            last_err = str(exc)
            continue
    return False, f"eth_call failed on all endpoints: {last_err}"


# --------------------------------------------------------------------------
# ABI helpers (only what the getters and simulations need)
# --------------------------------------------------------------------------
def enc_uint(v):
    return v.to_bytes(32, "big").hex()


def enc_addr(a):
    return "0" * 24 + a.lower().replace("0x", "")


def dec_uint(hexdata):
    if not hexdata or hexdata == "0x":
        return None
    return int(hexdata[2:66], 16)


def dec_bool(hexdata):
    v = dec_uint(hexdata)
    return None if v is None else (v != 0)


def dec_addr(hexdata):
    if not hexdata or len(hexdata) < 66:
        return None
    return "0x" + hexdata[26:66].lower()


def dec_revert(err):
    """Best-effort decode of an eth_call error into a short label."""
    if isinstance(err, dict):
        data = err.get("data") or ""
        msg = err.get("message", "")
        if isinstance(data, str) and data.startswith("0x") and len(data) >= 10:
            sel = data[:10].lower()
            if sel == "0x08c379a0":  # Error(string)
                try:
                    raw = bytes.fromhex(data[10:])
                    strlen = int.from_bytes(raw[32:64], "big")
                    return "revert: " + raw[64:64 + strlen].decode(errors="replace")
                except Exception:
                    return "revert (Error string, undecodable)"
            if sel in KNOWN_ERRORS:
                return f"revert: {KNOWN_ERRORS[sel]} ({sel})"
            return f"revert: custom error {sel}"
        if "execution reverted" in msg:
            return "revert (no error data)"
        return f"rpc error: {msg}"[:160]
    return f"error: {err}"[:160]


# --------------------------------------------------------------------------
# Getter table: (key, signature, argkind, decoder, category)
# argkind: none | wallet | one
# --------------------------------------------------------------------------
GETTERS = [
    ("totalSupply", "totalSupply()", "none", "uint", "supply"),
    ("totalMinted", "totalMinted()", "none", "uint", "supply"),
    ("totalShares", "totalShares()", "none", "uint", "supply"),
    ("maxSupply", "MAX_SUPPLY()", "none", "uint", "supply"),
    ("maxSupplyAlt", "maxSupply()", "none", "uint", "supply"),
    ("price", "price()", "none", "uint", "price"),
    ("mintPrice", "mintPrice()", "none", "uint", "price"),
    ("currentPrice", "currentPrice()", "none", "uint", "price"),
    ("getPrice", "getPrice()", "none", "uint", "price"),
    ("costOf1", "costOf(uint256)", "one", "uint", "price"),
    ("quote1", "quote(uint256)", "one", "uint", "price"),
    ("priceCents1", "priceCents(uint256)", "one", "uint", "price"),
    ("userShare", "USER_SHARE()", "none", "uint", "info"),
    ("paused", "paused()", "none", "bool", "status"),
    ("isLive", "isLive()", "none", "bool", "status"),
    ("opened", "opened()", "none", "bool", "status"),
    ("mintOpen", "mintOpen()", "none", "bool", "status"),
    ("saleActive", "saleActive()", "none", "bool", "status"),
    ("owner", "owner()", "none", "addr", "info"),
    ("agentRegistry", "agentRegistry()", "none", "addr", "gate"),
    ("registry", "registry()", "none", "addr", "gate"),
    ("registrar", "registrar()", "none", "addr", "gate"),
    ("identityResolver", "identityResolver()", "none", "addr", "gate"),
    ("agentIdContract", "AGENT_ID()", "none", "addr", "gate"),
    ("token", "token()", "none", "addr", "info"),
    ("startsAt", "startsAt()", "none", "uint", "time"),
    ("deadline", "deadline()", "none", "uint", "time"),
    ("walletBalance", "balanceOf(address)", "wallet", "uint", "wallet"),
    ("walletMintedBy", "mintedBy(address)", "wallet", "uint", "wallet"),
    ("walletMintedByWallet", "mintedByWallet(address)", "wallet", "uint", "wallet"),
    ("walletFreeMinted", "freeMinted(address)", "wallet", "uint", "wallet"),
    ("walletFreeClaimed", "freeClaimed(address)", "wallet", "bool", "wallet"),
    ("walletFreeRemaining", "freeRemaining(address)", "wallet", "uint", "wallet"),
    ("walletFreeLeft", "freeLeft(address)", "wallet", "uint", "wallet"),
    ("walletShares", "sharesOf(address)", "wallet", "uint", "wallet"),
    ("walletClaimed", "claimed(address)", "wallet", "bool", "wallet"),
    ("freeMintedGlobal", "freeMinted()", "none", "uint", "supply"),
    ("currentTarget", "currentTarget()", "none", "uint", "info"),
    ("currentReward", "currentReward()", "none", "uint", "info"),
    ("dailyRemaining", "dailyRemaining()", "none", "uint", "info"),
]


def run_getters(address, wallet):
    def one(spec):
        key, sig, argkind, dec, cat = spec
        data = selector(sig)
        if argkind == "wallet":
            if not wallet:
                return key, None
            data += enc_addr(wallet)
        elif argkind == "one":
            data += enc_uint(1)
        ok, res = eth_call(address, data)
        if not ok:
            return key, {"ok": False, "category": cat}
        val = {"uint": dec_uint, "bool": dec_bool, "addr": dec_addr}[dec](res)
        return key, {"ok": True, "value": val, "category": cat}

    out = {}
    with ThreadPoolExecutor(max_workers=8) as ex:
        for key, val in ex.map(one, GETTERS):
            if val is not None:
                out[key] = val
    return out


# --------------------------------------------------------------------------
# Sourcify + bytecode analysis
# --------------------------------------------------------------------------
def fetch_sourcify(address):
    url = f"https://sourcify.dev/server/v2/contract/56/{address}?fields=abi,compilation"
    req = urllib.request.Request(url, headers={"user-agent": "bsc-mint-precheck"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.loads(resp.read().decode())
        abi = payload.get("abi")
        comp = payload.get("compilation") or {}
        return {"verified": bool(abi), "abi": abi, "name": comp.get("name")}
    except Exception as exc:
        return {"verified": False, "abi": None, "name": None, "error": str(exc)[:120]}


def abi_signature(entry):
    def typ(inp):
        t = inp.get("type", "")
        if t.startswith("tuple"):
            inner = "(" + ",".join(typ(c) for c in inp.get("components", [])) + ")"
            return inner + ("[]" if t.endswith("[]") else "")
        return t
    return f"{entry.get('name')}({','.join(typ(i) for i in entry.get('inputs', []))})"


def abi_functions(abi):
    fns = []
    for entry in abi or []:
        if entry.get("type") != "function":
            continue
        sig = abi_signature(entry)
        fns.append({
            "name": entry.get("name"),
            "signature": sig,
            "selector": selector(sig),
            "mutability": entry.get("stateMutability"),
            "inputs": [i.get("type") for i in entry.get("inputs", [])],
        })
    return fns


def extract_selectors(code_hex):
    """Heuristic PUSH4 scan of runtime bytecode for function selectors."""
    raw = bytes.fromhex(code_hex[2:])
    sels = set()
    i = 0
    while i < len(raw) - 4:
        if raw[i] == 0x63:  # PUSH4
            sels.add("0x" + raw[i + 1:i + 5].hex())
            i += 5
        else:
            i += 1
    return sorted(sels)


def storage_at(address, slot):
    try:
        res = rpc("eth_getStorageAt", [address, slot, "latest"])
        if res and int(res, 16) != 0:
            return "0x" + res[-40:].lower()
    except Exception:
        pass
    return None


def analyze_code(address):
    code = rpc("eth_getCode", [address, "latest"])
    info = {"has_code": bool(code and code != "0x"), "code_size": (len(code) - 2) // 2 if code else 0}
    if not info["has_code"]:
        return info
    info["codehash"] = "0x" + keccak256(bytes.fromhex(code[2:])).hex()
    impl = storage_at(address, EIP1967_IMPL_SLOT)
    admin = storage_at(address, EIP1967_ADMIN_SLOT)
    minimal = code.startswith("0x363d3d373d3d3d363d73")
    info["proxy"] = {
        "eip1967_implementation": impl,
        "eip1967_admin": admin,
        "minimal_proxy": minimal,
        "is_proxy": bool(impl or minimal),
    }
    info["contains_space_id_registry"] = SPACE_ID_REGISTRY[2:] in code.lower()
    info["selectors"] = extract_selectors(code)
    if impl:
        try:
            impl_code = rpc("eth_getCode", [impl, "latest"])
            info["implementation_codehash"] = "0x" + keccak256(bytes.fromhex(impl_code[2:])).hex()
            info["implementation_contains_registry"] = SPACE_ID_REGISTRY[2:] in impl_code.lower()
            info["implementation_selectors"] = extract_selectors(impl_code)
        except Exception:
            pass
    return info


# --------------------------------------------------------------------------
# Fingerprint + history matching
# --------------------------------------------------------------------------
MINT_NAME_RE = re.compile(r"mint|claim|buy|join|participate", re.I)
COMMON_MINT_SIGS = [
    "mint(uint256)", "mint(address,uint256)", "mint()", "claim()", "claimFree()",
    "freeMint(bytes32,uint256,bytes)", "mine(uint256,uint256,uint256)",
    "buy(uint256)", "join()",
]
STRONG_MINT_SIGS = [
    "freeMint(bytes32,uint256,bytes)", "claimFree()",
    "claimFreeWithVoucher(uint256,bytes32,bytes32,uint256,bytes)",
    "mine(uint256,uint256,uint256)", "mineBatch(uint256,uint256[],uint256)",
]


def mint_functions(abi_fns):
    return [f for f in abi_fns if MINT_NAME_RE.search(f["name"] or "")
            and f["mutability"] in ("payable", "nonpayable")]


def make_fingerprint(mint_sels, is_proxy, gate_genuine):
    raw = json.dumps({"s": sorted(mint_sels), "p": bool(is_proxy), "g": bool(gate_genuine)}, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


def match_patterns(db, mint_sels, trait_haystack):
    patterns = []
    for row in db.execute("SELECT * FROM patterns"):
        pat = dict(row)
        pat_sels = set(json.loads(pat["selectors"] or "[]"))
        traits = json.loads(pat["traits"] or "[]")
        sel_set = set(mint_sels)
        union = sel_set | pat_sels
        jaccard = (len(sel_set & pat_sels) / len(union)) if union else 0.0
        hits = sum(1 for t in traits if t.lower() in trait_haystack)
        trait_ratio = hits / len(traits) if traits else 0.0
        score = 0.6 * jaccard + 0.4 * trait_ratio
        patterns.append({"pattern": pat, "score": round(score, 3), "jaccard": round(jaccard, 3),
                         "trait_hits": hits})
    patterns.sort(key=lambda x: x["score"], reverse=True)
    return patterns


# --------------------------------------------------------------------------
# Simulation of candidate mint calls (eth_call, value 0, read-only)
# --------------------------------------------------------------------------
def _sim_priority(fn):
    n = (fn.get("name") or "").lower()
    if "mint" in n:
        return 0
    if "claim" in n or "free" in n:
        return 1
    return 2


def simulate(address, wallet, candidates):
    results = []
    for fn in sorted(candidates, key=_sim_priority)[:6]:
        inputs = fn["inputs"]
        variants = []
        if inputs == []:
            variants = [("", "no args")]
        elif inputs == ["uint256"]:
            variants = [(enc_uint(0), "arg 0"), (enc_uint(1), "arg 1")]
        elif inputs == ["address"]:
            variants = [(enc_addr(wallet), "arg wallet")]
        else:
            results.append({"function": fn["signature"], "simulated": False,
                            "reason": "needs off-chain data or complex params"})
            continue
        for enc, label in variants:
            ok, res = eth_call(address, fn["selector"] + enc, from_addr=wallet, value=0)
            if ok:
                results.append({"function": fn["signature"], "variant": label,
                                "simulated": True, "success": True})
            else:
                results.append({"function": fn["signature"], "variant": label,
                                "simulated": True, "success": False, "error": dec_revert(res)})
    return results


# --------------------------------------------------------------------------
# Verdict + warnings
# --------------------------------------------------------------------------
def build_verdict(getters, sims, warnings):
    def val(key):
        g = getters.get(key)
        return g["value"] if g and g.get("ok") else None

    supply_now = val("totalMinted") if val("totalMinted") is not None else val("totalSupply")
    supply_max = val("maxSupply") if val("maxSupply") is not None else val("maxSupplyAlt")
    sold_out = supply_now is not None and supply_max is not None and supply_max > 0 and supply_now >= supply_max
    paused = val("paused") is True
    price_wei = None
    for key in ("costOf1", "price", "mintPrice", "currentPrice", "getPrice", "quote1"):
        if val(key) is not None:
            price_wei = val(key)
            break
    price_cents = val("priceCents1")
    voucher = any("voucher" in w.lower() for w in warnings)
    sim_ok = any(s.get("success") for s in sims)
    if sold_out:
        verdict = "CLOSED_OR_SOLDOUT"
    elif paused:
        verdict = "CLOSED_PAUSED"
    elif voucher:
        verdict = "NEEDS_VOUCHER_OR_SIGNATURE"
    elif (price_wei is not None and price_wei > 0) or (price_cents is not None and price_cents > 0):
        verdict = "PAID"
    elif sim_ok:
        verdict = "CANDIDATE_FREE"
    elif price_wei == 0:
        verdict = "LIKELY_FREE_UNSIMULATED"
    else:
        verdict = "UNKNOWN_NEEDS_AI_REVIEW"
    return {"verdict": verdict, "sold_out": sold_out, "paused": paused,
            "price_wei": price_wei, "price_cents": price_cents, "sim_success": sim_ok}


# --------------------------------------------------------------------------
# Experience database (SQLite)
# --------------------------------------------------------------------------
def db_connect():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute("""CREATE TABLE IF NOT EXISTS patterns (
        id TEXT PRIMARY KEY, name TEXT, family TEXT, outcome TEXT, mint_method TEXT,
        failure_reasons TEXT, notes TEXT, selectors TEXT, traits TEXT, updated_at TEXT)""")
    db.execute("""CREATE TABLE IF NOT EXISTS runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT, input TEXT, address TEXT,
        codehash TEXT, fingerprint TEXT, matched_pattern TEXT, match_score REAL,
        verdict TEXT, price_wei TEXT, warnings TEXT, timings TEXT)""")
    db.commit()
    return db


def seed_db(db, force=False):
    count = db.execute("SELECT COUNT(*) c FROM patterns").fetchone()["c"]
    if count and not force:
        return count
    with open(SEED_PATH) as fh:
        seed = json.load(fh)
    for pat in seed["patterns"]:
        sels = [selector(s) for s in pat.get("signatures", [])] + pat.get("literal_selectors", [])
        db.execute("""INSERT OR REPLACE INTO patterns
            (id, name, family, outcome, mint_method, failure_reasons, notes, selectors, traits, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                   (pat["id"], pat["name"], pat.get("family", ""), pat.get("outcome", ""),
                    pat.get("mint_method", ""), json.dumps(pat.get("failure_reasons", [])),
                    pat.get("notes", ""), json.dumps(sorted(set(sels))),
                    json.dumps(pat.get("traits", [])), time.strftime("%Y-%m-%dT%H:%M:%S%z")))
    db.commit()
    return db.execute("SELECT COUNT(*) c FROM patterns").fetchone()["c"]


# --------------------------------------------------------------------------
# Precheck orchestration
# --------------------------------------------------------------------------
class StageTimer:
    def __init__(self):
        self.timings = {}
        self._t = None
        self._name = None

    def start(self, name):
        self.stop()
        self._name = name
        self._t = time.perf_counter()

    def stop(self):
        if self._t is not None:
            self.timings[self._name] = round(time.perf_counter() - self._t, 3)
            self._t = None


def resolve_url(url):
    req = urllib.request.Request(url, headers={"user-agent": "Mozilla/5.0 (bsc-mint-precheck)"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        text = resp.read().decode(errors="replace")
    found = []
    for m in re.finditer(r"0x[0-9a-fA-F]{40}", text):
        a = m.group(0).lower()
        if a not in found:
            found.append(a)
    return found


def precheck(raw_input, wallet):
    timer = StageTimer()
    report = {"input": raw_input, "wallet": wallet, "stages": timer.timings}
    db = db_connect()
    seed_db(db)

    timer.start("resolve_input")
    address = None
    candidates = []
    if re.fullmatch(r"0x[0-9a-fA-F]{40}", raw_input.strip()):
        address = raw_input.strip().lower()
        report["input_kind"] = "contract_address"
    else:
        report["input_kind"] = "url"
        try:
            candidates = resolve_url(raw_input)
        except Exception as exc:
            report["error"] = f"URL fetch failed: {str(exc)[:140]}"
            timer.stop()
            return report
        for m in re.finditer(r"0x[0-9a-fA-F]{40}", raw_input):
            a = m.group(0).lower()
            if a not in candidates:
                candidates.insert(0, a)
        report["url_candidates"] = candidates
        # score every coded candidate: strong sale/claim selectors outweigh a
        # plain ERC20-style mint(address,uint256) that token contracts also carry
        known = {selector(s) for s in COMMON_MINT_SIGS}
        strong = {selector(s) for s in STRONG_MINT_SIGS}
        best = None
        for cand in candidates[:6]:
            try:
                code = rpc("eth_getCode", [cand, "latest"])
            except Exception:
                continue
            if not code or code == "0x":
                continue
            sels = set(extract_selectors(code))
            score = sum(3 if s in strong else 1 for s in sels & known)
            if best is None or score > best[1]:
                best = (cand, score)
        if best:
            address = best[0]
    if not address:
        report["error"] = "no contract address resolved from input"
        timer.stop()
        return report
    report["address"] = address
    timer.stop()

    timer.start("code_and_proxy")
    code_info = analyze_code(address)
    timer.stop()
    report["contract"] = code_info
    if not code_info.get("has_code"):
        report["verdict"] = {"verdict": "NOT_A_CONTRACT"}
        return report

    timer.start("sourcify")
    sourcify = fetch_sourcify(address)
    if code_info.get("proxy", {}).get("eip1967_implementation") and not sourcify.get("verified"):
        impl_src = fetch_sourcify(code_info["proxy"]["eip1967_implementation"])
        if impl_src.get("verified"):
            sourcify = impl_src
            sourcify["via_implementation"] = True
    timer.stop()
    report["sourcify"] = {"verified": sourcify.get("verified"), "name": sourcify.get("name"),
                          "via_implementation": sourcify.get("via_implementation", False)}

    abi_fns = abi_functions(sourcify.get("abi"))
    mint_fns = mint_functions(abi_fns)
    if mint_fns:
        mint_sels = [f["selector"] for f in mint_fns]
    else:
        present = set(code_info.get("selectors", [])) | set(code_info.get("implementation_selectors", []))
        mint_sels = sorted(present & {selector(s) for s in COMMON_MINT_SIGS})
    report["functions"] = {
        "mint_related": mint_fns,
        "mint_selectors": mint_sels,
        "abi_function_count": len(abi_fns),
        "bytecode_selector_count": len(code_info.get("selectors", [])),
    }

    timer.start("getters_parallel")
    getters = run_getters(address, wallet)
    timer.stop()
    report["getters"] = getters

    # gate evidence
    gate_values = []
    for key in ("agentRegistry", "registry", "registrar", "identityResolver", "agentIdContract"):
        g = getters.get(key)
        if g and g.get("ok") and g.get("value"):
            gate_values.append({"getter": key, "value": g["value"]})
    gate_genuine = any(g["value"] == SPACE_ID_REGISTRY for g in gate_values) or \
        code_info.get("contains_space_id_registry", False) or \
        code_info.get("implementation_contains_registry", False)
    report["gate"] = {"genuine_space_id": gate_genuine, "getters": gate_values,
                      "registry": SPACE_ID_REGISTRY}

    timer.start("history_match")
    haystack = " ".join([f["name"].lower() for f in abi_fns] +
                        [k.lower() for k, v in getters.items() if v.get("ok")])
    matches = match_patterns(db, mint_sels, haystack)
    best_match = matches[0] if matches and matches[0]["score"] >= 0.45 else None
    fingerprint = make_fingerprint(mint_sels, code_info.get("proxy", {}).get("is_proxy"), gate_genuine)
    report["fingerprint"] = fingerprint
    report["history_match"] = None
    if best_match:
        pat = best_match["pattern"]
        report["history_match"] = {
            "pattern_id": pat["id"], "name": pat["name"], "score": best_match["score"],
            "outcome": pat["outcome"], "mint_method": pat["mint_method"],
            "failure_reasons": json.loads(pat["failure_reasons"] or "[]"), "notes": pat["notes"],
        }
    timer.stop()

    timer.start("risk_and_simulation")
    warnings = []
    if not sourcify.get("verified"):
        warnings.append("Contract source is NOT verified on Sourcify: treat as higher risk.")
    if code_info.get("proxy", {}).get("is_proxy"):
        warnings.append("Upgradeable proxy: the implementation can change after this check.")
    if gate_values and not gate_genuine:
        warnings.append("HIGH: project exposes a registry-like getter that is NOT the real SPACE ID registry.")
    owner_g = getters.get("owner", {})
    if owner_g.get("ok") and owner_g.get("value") and int(owner_g["value"], 16) != 0:
        warnings.append("Owner is set (not renounced): the owner may pause or change terms.")
    voucher_names = [f for f in mint_fns if "voucher" in f["name"].lower()]
    sig_like = [f for f in mint_fns if f["inputs"] and f["inputs"][-1] == "bytes"
                and ("free" in f["name"].lower() or "claim" in f["name"].lower())]
    if voucher_names or sig_like:
        warnings.append("Mint path needs a voucher or server signature: it cannot be auto-minted and needs the project backend.")
    sim_candidates = mint_fns if mint_fns else [
        {"name": s, "signature": s, "selector": selector(s),
         "inputs": [p for p in s[s.find("(") + 1:-1].split(",") if p]}
        for s in COMMON_MINT_SIGS if selector(s) in mint_sels]
    sims = simulate(address, wallet, sim_candidates)
    timer.stop()
    report["simulations"] = sims
    report["warnings"] = warnings

    verdict = build_verdict(getters, sims, warnings)
    report["verdict"] = verdict
    if best_match and best_match["score"] >= 0.45:
        verdict["matched_pattern"] = best_match["pattern"]["id"]
        if verdict["verdict"] == "UNKNOWN_NEEDS_AI_REVIEW":
            verdict["verdict"] = "MATCHED_KNOWN_PATTERN"
            verdict["note"] = ("Known family from the experience database: reuse its mint method, "
                                "but every live value in this report was rechecked on-chain.")

    try:
        db.execute("""INSERT INTO runs (created_at, input, address, codehash, fingerprint,
            matched_pattern, match_score, verdict, price_wei, warnings, timings)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                   (time.strftime("%Y-%m-%dT%H:%M:%S%z"), raw_input, address,
                    code_info.get("codehash"), fingerprint,
                    report["history_match"]["pattern_id"] if report["history_match"] else None,
                    report["history_match"]["score"] if report["history_match"] else None,
                    verdict["verdict"], str(verdict.get("price_wei")),
                    json.dumps(warnings), json.dumps(timer.timings)))
        db.commit()
    except Exception:
        pass
    return report


def human_summary(r):
    if r.get("error"):
        return f"PRECHECK GAGAL: {r['error']}"
    v = r.get("verdict", {})
    lines = [f"Verdict: {v.get('verdict')}"]
    lines.append(f"Kontrak: {r.get('address')}")
    if r.get("sourcify"):
        lines.append(f"Sourcify verified: {r['sourcify'].get('verified')} ({r['sourcify'].get('name')})")
    if r.get("gate"):
        lines.append(f"Gate SPACE ID asli: {r['gate'].get('genuine_space_id')}")
    if v.get("price_wei") is not None:
        lines.append(f"Harga: {v['price_wei']} wei (sekitar {v['price_wei'] / 1e18:.6f} dalam unit 18 desimal kontrak)")
    if v.get("price_cents") is not None:
        lines.append(f"Harga (cents getter): {v['price_cents']}")
    if r.get("history_match"):
        hm = r["history_match"]
        lines.append(f"Cocok pola historis: {hm['name']} (skor {hm['score']}, outcome {hm['outcome']})")
        for fr in hm.get("failure_reasons", []):
            lines.append(f"  - alasan gagal historis: {fr}")
    for s in r.get("simulations", []):
        if s.get("simulated"):
            lines.append(f"Simulasi {s['function']} ({s.get('variant')}): "
                         f"{'SUKSES' if s.get('success') else s.get('error')}")
    for w in r.get("warnings", []):
        lines.append(f"PERINGATAN: {w}")
    total = sum(r.get("stages", {}).values())
    lines.append(f"Tahapan: {r.get('stages')} (total {total:.2f}s)")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def self_test():
    assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", "keccak empty"
    assert selector("mint(address,uint256)") == "0x40c10f19"
    assert selector("balanceOf(address)") == "0x70a08231"
    assert selector("totalSupply()") == "0x18160ddd"
    assert selector("owner()") == "0x8da5cb5b"
    assert dec_uint("0x" + enc_uint(12345)) == 12345
    print("self-test OK: keccak256 + selectors + ABI codec")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="bsc_mint_precheck")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("self-test")
    p_init = sub.add_parser("init-db")
    p_init.add_argument("--force-seed", action="store_true")
    p_pre = sub.add_parser("precheck")
    p_pre.add_argument("input")
    p_pre.add_argument("--wallet", default="0xB384D3070ab3AC46FDfE0Fbf6340EEa78075F66e")
    p_pre.add_argument("--human", action="store_true")
    p_pre.add_argument("--out")
    p_hist = sub.add_parser("history")
    p_hist.add_argument("--limit", type=int, default=10)
    p_learn = sub.add_parser("learn")
    p_learn.add_argument("--pattern-id", required=True)
    p_learn.add_argument("--name", required=True)
    p_learn.add_argument("--family", default="")
    p_learn.add_argument("--outcome", required=True)
    p_learn.add_argument("--method", default="")
    p_learn.add_argument("--failures", default="")
    p_learn.add_argument("--notes", default="")
    p_learn.add_argument("--signatures", default="")
    p_learn.add_argument("--traits", default="")
    args = ap.parse_args(argv)

    if args.cmd == "self-test":
        self_test()
        return 0
    if args.cmd == "init-db":
        db = db_connect()
        n = seed_db(db, force=args.force_seed)
        print(f"db ready at {DB_PATH} with {n} patterns")
        return 0
    if args.cmd == "precheck":
        report = precheck(args.input, args.wallet)
        text = json.dumps(report, indent=1, default=str)
        if args.out:
            with open(args.out, "w") as fh:
                fh.write(text)
        print(human_summary(report) if args.human else text)
        return 0
    if args.cmd == "history":
        db = db_connect()
        seed_db(db)
        print("== pola tersimpan ==")
        for row in db.execute("SELECT id, name, outcome FROM patterns ORDER BY id"):
            print(f"- {row['id']}: {row['name']} (outcome: {row['outcome']})")
        print("== run terakhir ==")
        for row in db.execute("SELECT created_at, input, address, matched_pattern, verdict FROM runs ORDER BY id DESC LIMIT ?", (args.limit,)):
            print(f"- {row['created_at']} {str(row['input'])[:44]} -> {row['address']} "
                  f"match={row['matched_pattern']} verdict={row['verdict']}")
        return 0
    if args.cmd == "learn":
        db = db_connect()
        seed_db(db)
        sigs = [s.strip() for s in args.signatures.split(";") if s.strip()]
        sels = sorted({selector(s) for s in sigs})
        failures = [s.strip() for s in args.failures.split(";") if s.strip()]
        traits = [s.strip() for s in args.traits.split(",") if s.strip()]
        db.execute("""INSERT OR REPLACE INTO patterns
            (id, name, family, outcome, mint_method, failure_reasons, notes, selectors, traits, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                   (args.pattern_id, args.name, args.family, args.outcome, args.method,
                    json.dumps(failures), args.notes, json.dumps(sels), json.dumps(traits),
                    time.strftime("%Y-%m-%dT%H:%M:%S%z")))
        db.commit()
        print(f"pattern saved: {args.pattern_id} ({len(sels)} selectors, {len(traits)} traits)")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
