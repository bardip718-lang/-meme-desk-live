#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MEME DESK LIVE v3: live crypto market-intelligence terminal (RESEARCH ONLY)

This app analyses public market data. It does not trade, simulate trades, hold keys or talk to brokers.
Every number shown comes from a documented API or from prices this app collected itself (labelled).

Run (Pydroid 3): open this file, tap the yellow play button, then open http://127.0.0.1:8765 in Chrome.
Needs:           Python 3.8+ and nothing else (standard library only).
Optional keys:   AI provider key, Solana RPC URL, CoinGecko demo key. Enter them in Settings (stored only
                 on this device in meme_desk_secrets.json) or set DESK_AI_KEY / DESK_SOL_RPC / DESK_CG_KEY.
Not financial advice. Trending, boosted and brand-new tokens are frequently scams.
"""
import base64, calendar, hmac, json, math, os, re, secrets as pysecrets, shutil, signal, socket, statistics
import sys, threading, time, urllib.error, urllib.parse, urllib.request
from collections import OrderedDict, defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "3.0.0"
HOST = "0.0.0.0" if "PORT" in os.environ else os.environ.get("DESK_HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", os.environ.get("DESK_PORT", "8765")))
PUBLIC_AUTH_USER = os.environ.get("DESK_USERNAME", "")
PUBLIC_AUTH_PASSWORD = os.environ.get("DESK_PASSWORD", "")
DATA_DIR = os.environ.get("DESK_DATA_DIR", os.getcwd())
DS_BASE = os.environ.get("DESK_DS_BASE", "https://api.dexscreener.com")
GT_BASE_FREE = os.environ.get("DESK_GT_BASE", "https://api.geckoterminal.com/api/v2")
GT_BASE_KEYED = os.environ.get("DESK_CG_BASE", "https://api.coingecko.com/api/v3/onchain")
AI_URL_OVERRIDE = os.environ.get("DESK_AI_URL", "")
DEFAULT_SOL_RPC = "https://api.mainnet-beta.solana.com"
STATE_FILE = os.path.join(DATA_DIR, "meme_desk_state.json")
OLD_STATE_FILE = os.path.join(DATA_DIR, "paper_state.json")     # from v1/v2; only the watchlist is imported, file is never modified
CONFIG_FILE = os.path.join(DATA_DIR, "meme_desk_config.json")
SECRETS_FILE = os.path.join(DATA_DIR, "meme_desk_secrets.json")
TOKEN = pysecrets.token_urlsafe(18)          # per-run token: stops other websites from posting to this local server
BACKOFF = 1.0
W = ("m5", "h1", "h6", "h24")

LOCK = threading.RLock()
STOP = threading.Event()
WAKE = threading.Event()


class ApiError(Exception):
    def __init__(self, msg, fatal=False):
        super().__init__(msg)
        self.fatal = fatal


# ----------------------------------------------------------------------------- settings
DEFAULTS = {
    "refresh_s": 30, "max_tracked": 60, "discovery": True, "min_liq_discovery": 10000.0, "chains": [],
    "min_liq": 25000.0, "min_age_h": 2.0, "whale_usd": 5000.0, "whale_liq_pct": 1.0,
    "trades_per_cycle": 2, "gt_rpm": 10,
    "ai_provider": "anthropic", "ai_model": "claude-sonnet-5-5", "ai_base": "https://api.openai.com/v1", "ai_max_age_min": 30.0,
}
SCHEMA = {  # name: (type, min, max)
    "refresh_s": (float, 15, 600), "max_tracked": (int, 10, 100), "discovery": (bool,),
    "min_liq_discovery": (float, 0, 1e9), "min_liq": (float, 0, 1e9), "min_age_h": (float, 0, 1e5),
    "whale_usd": (float, 100, 1e9), "whale_liq_pct": (float, 0.1, 100), "trades_per_cycle": (int, 0, 10),
    "gt_rpm": (int, 3, 30), "ai_max_age_min": (float, 1, 1440),
}
KEY_RE = re.compile(r"^[a-z0-9\-]{2,30}:[A-Za-z0-9_\-]{10,100}$")
ADDR_RE = re.compile(r"^[A-Za-z0-9_\-]{20,100}$")
SOL_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")

S = {"ver": 0, "settings": dict(DEFAULTS), "secrets": {}, "coins": {}, "hist": {}, "watch": [], "wallets": [],
     "feed": [], "warn": [], "agents": {}, "ai": {"coins": {}, "history": [], "busy": False, "error": None, "seq": 0},
     "onchain": {}, "ohlcv": {}, "trades": {}, "overview": None, "launch": {}, "last_fetch": {}, "focus": {},
     "cycle": {"n": 0, "start": 0, "end": 0, "ms": 0, "errors": [], "found": 0}}


def bump():
    with LOCK:
        S["ver"] += 1


def log(msg, kind=""):
    with LOCK:
        S["feed"].insert(0, {"t": time.time(), "m": str(msg)[:300], "k": kind})
        del S["feed"][100:]


def warn(msg):
    with LOCK:
        if msg not in S["warn"]:
            S["warn"].append(msg)
    log(msg, "wn")


def clean(o):
    """Replace NaN/inf so the browser's JSON.parse never fails."""
    if isinstance(o, float):
        return o if math.isfinite(o) else None
    if isinstance(o, dict):
        return {str(k): clean(v) for k, v in o.items()}
    if isinstance(o, (list, tuple, deque)):
        return [clean(v) for v in o]
    return o


def atomic_write(path, obj, private=False):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(clean(obj), f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    if private:
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def quarantine(path, why):
    dest = "%s.corrupt-%d" % (path, int(time.time()))
    try:
        os.replace(path, dest)
        warn("%s was unreadable (%s). Moved to %s and started fresh." % (os.path.basename(path), why, os.path.basename(dest)))
    except OSError as e:
        warn("Could not read %s (%s) and could not move it aside: %s" % (os.path.basename(path), why, e))


def valid_https(u, allow_local=True):
    try:
        p = urllib.parse.urlparse(u)
    except ValueError:
        return False
    if p.scheme == "https" and p.hostname:
        return True
    return allow_local and p.scheme == "http" and p.hostname in ("localhost", "127.0.0.1")


def clean_settings(inp, cur):
    out = dict(cur)
    for k, v in inp.items():
        if k in SCHEMA:
            sp = SCHEMA[k]
            if sp[0] is bool:
                if not isinstance(v, bool):
                    raise ValueError("%s must be on or off" % k)
                out[k] = v
            else:
                if isinstance(v, bool) or not isinstance(v, (int, float, str)):
                    raise ValueError("%s must be a number" % k)
                try:
                    x = float(v)
                except ValueError:
                    raise ValueError("%s must be a number" % k)
                if not math.isfinite(x) or x < sp[1] or x > sp[2]:
                    raise ValueError("%s must be between %s and %s" % (k, sp[1], sp[2]))
                out[k] = int(x) if sp[0] is int else x
        elif k == "ai_provider":
            if v not in ("anthropic", "openai"):
                raise ValueError("ai_provider must be anthropic or openai")
            out[k] = v
        elif k == "ai_model":
            if not isinstance(v, str) or not re.match(r"^[\w.\-:/]{1,100}$", v):
                raise ValueError("ai_model contains invalid characters")
            out[k] = v
        elif k == "ai_base":
            if not isinstance(v, str) or not valid_https(v.strip()) or len(v) > 200:
                raise ValueError("ai_base must be an https URL (http only for localhost)")
            out[k] = v.strip()
        elif k == "chains":
            if not isinstance(v, list) or len(v) > 20 or not all(isinstance(x, str) and re.match(r"^[a-z0-9\-]{2,30}$", x) for x in v):
                raise ValueError("chains must be a list of lowercase chain ids")
            out[k] = v
    return out


def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, encoding="utf-8") as f:
                raw = json.load(f)
            if not isinstance(raw, dict):
                raise ValueError("not a JSON object")
            S["settings"] = clean_settings(raw, dict(DEFAULTS))
            if set(raw) - set(DEFAULTS):       # old paper-trading keys are dropped on the next save
                log("Removed obsolete paper-trading settings from the config file", "wn")
        except Exception as e:
            quarantine(CONFIG_FILE, str(e)[:80])
    if os.path.exists(SECRETS_FILE):
        try:
            with open(SECRETS_FILE, encoding="utf-8") as f:
                raw = json.load(f)
            S["secrets"] = {k: v for k, v in raw.items() if k in ("ai_key", "sol_rpc", "cg_key") and isinstance(v, str)}
        except Exception as e:
            quarantine(SECRETS_FILE, str(e)[:80])


ENVN = {"ai_key": "DESK_AI_KEY", "sol_rpc": "DESK_SOL_RPC", "cg_key": "DESK_CG_KEY"}


def secret(name):
    return os.environ.get(ENVN[name]) or S["secrets"].get(name) or ""


def save_config():
    with LOCK:
        atomic_write(CONFIG_FILE, S["settings"])


def save_secrets():
    with LOCK:
        atomic_write(SECRETS_FILE, S["secrets"], private=True)


def scrub(m):
    m = str(m)
    for n in ENVN:
        v = secret(n)
        if v and len(v) >= 6:
            m = m.replace(v, "***")
    return re.sub(r"((?:api[_-]?)?key|token|secret)=[^&\s]+", r"\1=***", m, flags=re.I)


# ----------------------------------------------------------------------------- HTTP client with limits
class Prov:
    def __init__(self, name, rpm, note=""):
        self.name, self.rpm, self.note = name, rpm, note
        self.t = deque()
        self.lock = threading.Lock()
        self.status, self.last_ok, self.last_err = "idle", 0.0, ""
        self.blocked_until, self.calls, self.errors = 0.0, 0, 0

    def wait(self):
        while True:
            with self.lock:
                now = time.time()
                while self.t and now - self.t[0] >= 60:
                    self.t.popleft()
                w = max(0.0, self.blocked_until - now)
                if w == 0 and len(self.t) < self.rpm:
                    self.t.append(now)
                    return
                if w == 0:
                    w = 60 - (now - self.t[0])
            if w > 20:
                self.status = "rate_limited"
                raise ApiError("%s: rate limit reached, retry in about %ds" % (self.name, int(w)))
            if STOP.wait(min(w, 5.0)):
                raise ApiError("shutting down", True)

    def block(self, secs):
        with self.lock:
            self.blocked_until = max(self.blocked_until, time.time() + secs)
        self.status = "rate_limited"

    def good(self):
        self.status, self.last_ok = "ok", time.time()

    def bad(self, msg):
        self.status, self.last_err = "error", scrub(msg)
        self.errors += 1

    def snap(self):
        return {"name": self.name, "status": self.status, "last_ok": self.last_ok, "last_error": self.last_err,
                "calls": self.calls, "errors": self.errors, "rpm_limit": self.rpm, "note": self.note,
                "blocked_s": max(0, int(self.blocked_until - time.time()))}


P_DS = Prov("DexScreener (pairs/search)", 200, "documented 300/min; app stays below")
P_BOOST = Prov("DexScreener (discovery lists)", 45, "documented 60/min; app stays below")
P_GT = Prov("GeckoTerminal (trades, charts, new pools)", 10, "keyless public API; limit set in Settings")
P_RPC = Prov("Solana RPC (holders, wallet lookup)", 20, "public RPC is rate limited; optional custom RPC")
P_AI = Prov("AI provider", 12, "your own API key; billed by the provider")
PROVS = [P_DS, P_BOOST, P_GT, P_RPC, P_AI]


def http(prov, url, data=None, headers=None, timeout=15, retries=3, max_bytes=4000000):
    hdrs = {"User-Agent": "meme-desk/" + VERSION, "Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    body = None
    if data is not None:
        body = json.dumps(data).encode()
        hdrs["Content-Type"] = "application/json"
    last = None
    for attempt in range(retries):
        if STOP.is_set():
            raise ApiError("shutting down", True)
        prov.wait()
        prov.calls += 1
        try:
            req = urllib.request.Request(url, data=body, headers=hdrs, method="POST" if body is not None else "GET")
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read(max_bytes + 1)
            if len(raw) > max_bytes:
                raise ApiError("%s: response too large" % prov.name, True)
            try:
                out = json.loads(raw.decode("utf-8", "replace"))
            except ValueError:
                raise ApiError("%s: response was not valid JSON" % prov.name)
            prov.good()
            return out
        except ApiError as e:
            last = e
            if e.fatal:
                prov.bad(str(e))
                raise
        except urllib.error.HTTPError as e:
            code = e.code
            if code == 429:
                ra = e.headers.get("Retry-After") if e.headers else None
                try:
                    delay = float(ra)
                except (TypeError, ValueError):
                    delay = min(2 ** (attempt + 2), 60)
                prov.block(max(0.0, min(delay, 60.0)))
                last = ApiError("%s: rate limited (HTTP 429)" % prov.name)
            elif code >= 500:
                last = ApiError("%s: server error (HTTP %d)" % (prov.name, code))
            else:
                msg = ""
                try:
                    j = json.loads(e.read(2000).decode("utf-8", "replace"))
                    er = j.get("error")
                    msg = er.get("message", "") if isinstance(er, dict) else (er or j.get("message") or "")
                except Exception:
                    pass
                err = ApiError(scrub("%s: HTTP %d %s" % (prov.name, code, str(msg)[:200])).strip(), True)
                prov.bad(str(err))
                raise err
        except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, OSError) as e:
            last = ApiError(scrub("%s: connection problem (%s)" % (prov.name, str(getattr(e, "reason", e))[:120])))
        if attempt < retries - 1:
            STOP.wait(BACKOFF * (2 ** attempt))
    prov.bad(str(last))
    raise last


# ----------------------------------------------------------------------------- data providers
def fnum(x):
    try:
        v = float(x)
        return v if math.isfinite(v) else None
    except (TypeError, ValueError):
        return None


def s64(x):
    return None if x is None else str(x)[:64]


def safe_url(u, prefix=("https://",)):
    return u if isinstance(u, str) and len(u) < 300 and u.startswith(prefix) and not re.search(r"[\s<>\"']", u) else None


def norm(p):
    """DexScreener pair object -> coin dict. Missing fields stay None (never invented)."""
    if not isinstance(p, dict):
        return None
    base, quote = p.get("baseToken") or {}, p.get("quoteToken") or {}
    chain, addr, price = p.get("chainId"), base.get("address"), fnum(p.get("priceUsd"))
    if not isinstance(chain, str) or not isinstance(addr, str) or price is None or price <= 0:
        return None
    if not KEY_RE.match(chain + ":" + addr):
        return None
    pc, vol, tx, liq = p.get("priceChange") or {}, p.get("volume") or {}, p.get("txns") or {}, p.get("liquidity") or {}
    info = p.get("info") if isinstance(p.get("info"), dict) else {}
    links = []
    for w_ in info.get("websites") or []:
        u = safe_url(w_.get("url")) if isinstance(w_, dict) else None
        if u:
            links.append(["Website", u])
    for s_ in info.get("socials") or []:
        u = safe_url(s_.get("url")) if isinstance(s_, dict) else None
        if u:
            links.append([str(s_.get("type", "link"))[:20].capitalize(), u])

    def txn(w):
        t = tx.get(w) or {}
        return {"buys": fnum(t.get("buys")), "sells": fnum(t.get("sells"))}
    return {"key": chain + ":" + addr, "chain": chain, "addr": addr, "name": s64(base.get("name")),
            "sym": s64(base.get("symbol")) or "?", "price": price,
            "chg": {w: fnum(pc.get(w)) for w in W}, "vol": {w: fnum(vol.get(w)) for w in W},
            "tx": {w: txn(w) for w in W}, "liq": fnum(liq.get("usd")), "fdv": fnum(p.get("fdv")),
            "mcap": fnum(p.get("marketCap")), "created": fnum(p.get("pairCreatedAt")), "dex": s64(p.get("dexId")),
            "pair": s64(p.get("pairAddress")), "url": safe_url(p.get("url"), ("https://dexscreener.com/",)),
            "logo": safe_url(info.get("imageUrl"), ("https://cdn.dexscreener.com/",)), "links": links[:6],
            "boosts": fnum((p.get("boosts") or {}).get("active")) if isinstance(p.get("boosts"), dict) else None,
            "quote": {"sym": s64(quote.get("symbol"))}, "updated": time.time()}


def best_pairs(pairs, wanted=None):
    best = {}
    for p in pairs if isinstance(pairs, list) else []:
        c = norm(p)
        if not c or (wanted is not None and c["addr"].lower() not in wanted):
            continue
        old = best.get(c["key"])
        if old is None or (c["liq"] or 0) > (old["liq"] or 0):
            best[c["key"]] = c
    return best


def pump_info(c):
    """Pump.fun relation. Pump.fun has NO official public data API, so this is a labelled heuristic from public fields."""
    dex, ev = (c.get("dex") or "").lower(), []
    if c["chain"] != "solana":
        return None
    if "pump" in dex:
        ev.append("DexScreener lists the pool on '%s'" % c["dex"])
    suffix = c["addr"].endswith("pump")
    if suffix:
        ev.append("mint address ends with 'pump' (the naming pattern Pump.fun mints use; not proof)")
    if not ev:
        return None
    if dex == "pumpfun":
        status = "On the Pump.fun bonding curve (per DexScreener)"
    elif dex == "pumpswap":
        status = "Graduated to PumpSwap (per DexScreener)"
    elif suffix and "pump" not in dex:
        status = "Probably graduated: trades on %s (inferred from the mint pattern, unconfirmed)" % (c["dex"] or "another DEX")
    else:
        status = "Pump.fun related (status unclear)"
    return {"status": status, "evidence": ev, "bonding_pct": None,
            "note": "Bonding-curve progress and creator data are not available from the free sources used here."}


def ds_list(kind):
    path = {"top": "/token-boosts/top/v1", "latest": "/token-boosts/latest/v1", "profiles": "/token-profiles/latest/v1"}[kind]
    data = http(P_BOOST, DS_BASE + path)
    out = []
    for d in data if isinstance(data, list) else []:
        if isinstance(d, dict) and isinstance(d.get("chainId"), str) and isinstance(d.get("tokenAddress"), str):
            if KEY_RE.match(d["chainId"] + ":" + d["tokenAddress"]):
                out.append((d["chainId"], d["tokenAddress"]))
    return out


def ds_tokens(chain, addrs):
    return http(P_DS, "%s/tokens/v1/%s/%s" % (DS_BASE, chain, ",".join(addrs)))


def ds_search(q):
    data = http(P_DS, DS_BASE + "/latest/dex/search?q=" + urllib.parse.quote(q))
    return data.get("pairs") if isinstance(data, dict) else []


def gt_base():
    return GT_BASE_KEYED if secret("cg_key") else GT_BASE_FREE


def gt_headers():
    return {"x-cg-demo-api-key": secret("cg_key")} if secret("cg_key") else None


def gt_get(path, retries=2):
    P_GT.rpm = S["settings"]["gt_rpm"]
    return http(P_GT, gt_base() + path, headers=gt_headers(), retries=retries)


GT_NET = {"solana": "solana", "ethereum": "eth", "base": "base", "bsc": "bsc", "arbitrum": "arbitrum",
          "polygon": "polygon_pos", "avalanche": "avax", "optimism": "optimism", "sui": "sui-network",
          "ton": "ton", "tron": "tron"}


PATH_ID = re.compile(r"^[A-Za-z0-9_\-]{10,100}$")


def iso_to_ts(s):
    try:
        return float(calendar.timegm(time.strptime(s[:19], "%Y-%m-%dT%H:%M:%S")))
    except (ValueError, TypeError):
        return None


def get_trades(c):
    """Real transactions for a pool from the documented GeckoTerminal/CoinGecko on-chain 'pool trades' endpoint (last 300 in 24h)."""
    net = GT_NET.get(c["chain"])
    if not net or not c.get("pair") or not PATH_ID.match(c["pair"]):
        raise ApiError("Transaction data is not available for this chain/pool", True)
    data = gt_get("/networks/%s/pools/%s/trades?token=%s" % (net, c["pair"], c["addr"]))
    rows = data.get("data") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        raise ApiError("GeckoTerminal: unexpected trades response format")
    out = []
    for r in rows:
        a = (r or {}).get("attributes") if isinstance(r, dict) else None
        if not isinstance(a, dict):
            continue
        ts, usd = iso_to_ts(a.get("block_timestamp")), fnum(a.get("volume_in_usd"))
        h, w, kind = a.get("tx_hash"), a.get("tx_from_address"), a.get("kind")
        if ts is None or usd is None or usd < 0 or kind not in ("buy", "sell"):
            continue
        if not (isinstance(h, str) and re.match(r"^[A-Za-z0-9]{10,120}$", h)) or not (isinstance(w, str) and ADDR_RE.match(w)):
            continue
        amt = fnum(a.get("to_token_amount") if kind == "buy" else a.get("from_token_amount"))
        out.append({"t": ts, "kind": kind, "usd": usd, "wallet": w, "tx": h, "amt": amt,
                    "px": fnum(a.get("price_to_in_usd") if kind == "buy" else a.get("price_from_in_usd"))})
    return out


def gt_new_solana_pools():
    data = gt_get("/networks/solana/new_pools?page=1")
    out = []
    for it in data.get("data", []) if isinstance(data, dict) else []:
        try:
            bid = it["relationships"]["base_token"]["data"]["id"]
            dex = it["relationships"]["dex"]["data"]["id"]
            addr = bid.split("_", 1)[1]
            created = iso_to_ts(it["attributes"].get("pool_created_at"))
        except (KeyError, TypeError, IndexError, AttributeError):
            continue
        if KEY_RE.match("solana:" + addr) and isinstance(dex, str):
            out.append({"addr": addr, "dex": dex[:40], "created": created, "name": str(it["attributes"].get("name", ""))[:60]})
    return out


def rpc_call(method, params, timeout=20):
    rpc = secret("sol_rpc") or DEFAULT_SOL_RPC
    r = http(P_RPC, rpc, {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=timeout, retries=2)
    if isinstance(r, dict) and r.get("error"):
        m = r["error"].get("message", "RPC error") if isinstance(r["error"], dict) else "RPC error"
        raise ApiError(scrub("Solana RPC: %s" % str(m)[:160]), True)
    if not isinstance(r, dict) or "result" not in r:
        raise ApiError("Solana RPC: unexpected response format")
    return r["result"]


def solana_holders(addr):
    if not SOL_RE.match(addr):
        raise ApiError("Not a valid Solana token address", True)
    sup, big = rpc_call("getTokenSupply", [addr]), rpc_call("getTokenLargestAccounts", [addr])
    try:
        supply = float(sup["value"]["uiAmountString"])
        accts = [(a["address"], float(a["uiAmountString"])) for a in big["value"]]
    except (KeyError, TypeError, ValueError):
        raise ApiError("Solana RPC: unexpected response format")
    if supply <= 0 or not accts:
        raise ApiError("Solana RPC: no supply or holder data returned")
    pcts = [100.0 * a[1] / supply for a in accts]
    return {"supply": supply, "top1_pct": pcts[0], "top5_pct": sum(pcts[:5]), "top10_pct": sum(pcts[:10]),
            "n_accounts": len(accts), "top": [{"acct": a[0][:6] + "…" + a[0][-4:], "pct": p} for a, p in zip(accts[:10], pcts)],
            "fetched": time.time(), "source": urllib.parse.urlparse(secret("sol_rpc") or DEFAULT_SOL_RPC).hostname,
            "caveat": "These are token accounts, not people. Liquidity-pool vaults, exchanges and burn/lock accounts often appear as the largest holders. Only the 20 largest accounts are visible."}


def solana_wallet_lookup(addr):
    if not SOL_RE.match(addr):
        raise ApiError("Not a valid Solana wallet address", True)
    sigs = rpc_call("getSignaturesForAddress", [addr, {"limit": 20}])
    bal = rpc_call("getBalance", [addr])
    out = []
    for s in sigs if isinstance(sigs, list) else []:
        if isinstance(s, dict) and isinstance(s.get("signature"), str) and re.match(r"^[1-9A-HJ-NP-Za-km-z]{60,100}$", s["signature"]):
            out.append({"sig": s["signature"], "t": fnum(s.get("blockTime")), "failed": bool(s.get("err"))})
    lam = fnum(bal.get("value")) if isinstance(bal, dict) else None
    return {"address": addr, "sol": None if lam is None else lam / 1e9, "recent": out, "fetched": time.time(),
            "note": "Signatures only: this app does not decode what each transaction did. Open the explorer link for details."}


EXPL = {"solana": ("https://solscan.io/token/%s", "https://solscan.io/tx/%s", "https://solscan.io/account/%s"),
        "ethereum": ("https://etherscan.io/token/%s", "https://etherscan.io/tx/%s", "https://etherscan.io/address/%s"),
        "base": ("https://basescan.org/token/%s", "https://basescan.org/tx/%s", "https://basescan.org/address/%s"),
        "bsc": ("https://bscscan.com/token/%s", "https://bscscan.com/tx/%s", "https://bscscan.com/address/%s"),
        "arbitrum": ("https://arbiscan.io/token/%s", "https://arbiscan.io/tx/%s", "https://arbiscan.io/address/%s"),
        "polygon": ("https://polygonscan.com/token/%s", "https://polygonscan.com/tx/%s", "https://polygonscan.com/address/%s"),
        "avalanche": ("https://snowtrace.io/token/%s", "https://snowtrace.io/tx/%s", "https://snowtrace.io/address/%s"),
        "optimism": ("https://optimistic.etherscan.io/token/%s", "https://optimistic.etherscan.io/tx/%s", "https://optimistic.etherscan.io/address/%s")}


def explorer(chain, kind, ident):
    t = EXPL.get(chain)
    return t[{"token": 0, "tx": 1, "wallet": 2}[kind]] % ident if t and re.match(r"^[A-Za-z0-9]{10,120}$", ident or "") else None


def age_h(c):
    cr = c.get("created")
    return None if not cr else max(0.0, (time.time() * 1000 - cr) / 3.6e6)


def is_stale(c):
    lim = max(90, 3 * S["settings"]["refresh_s"]) if c.get("mon") else 600
    return time.time() - c["updated"] > lim


# ----------------------------------------------------------------------------- persistence (watchlist + tracked wallets only)
def save_state():
    with LOCK:
        atomic_write(STATE_FILE, {"version": 3, "saved": time.time(), "watch": S["watch"], "wallets": S["wallets"]})


def load_state():
    src = None
    if os.path.exists(STATE_FILE):
        src = STATE_FILE
    elif os.path.exists(OLD_STATE_FILE):
        src = OLD_STATE_FILE
    if not src:
        return
    try:
        with open(src, encoding="utf-8") as f:
            raw = json.load(f)
        if not isinstance(raw, dict):
            raise ValueError("not a JSON object")
    except Exception as e:
        quarantine(src, str(e)[:80])
        return
    with LOCK:
        S["watch"] = [k for k in raw.get("watch", []) if isinstance(k, str) and KEY_RE.match(k)][:50]
        for w in raw.get("wallets", []) if src == STATE_FILE else []:
            if isinstance(w, dict) and isinstance(w.get("addr"), str) and ADDR_RE.match(w["addr"]) and isinstance(w.get("chain"), str):
                S["wallets"].append({"addr": w["addr"], "chain": w["chain"][:30], "label": str(w.get("label", ""))[:40]})
        if src == OLD_STATE_FILE:
            log("Imported your watchlist from the old paper_state.json. All paper-trading data was dropped. You can delete that file; this app no longer reads it after the first save.", "wn")


# ----------------------------------------------------------------------------- transactions store and analytics
def store_trades(key, rows):
    with LOCK:
        t = S["trades"].setdefault(key, {"rows": OrderedDict(), "fetched": 0, "error": None})
        for r in rows:
            t["rows"][(r["tx"], r["kind"], round(r["usd"], 4))] = r
        if len(t["rows"]) > 600:
            keep = sorted(t["rows"].items(), key=lambda kv: -kv[1]["t"])[:600]
            t["rows"] = OrderedDict(keep)
        t["fetched"], t["error"] = time.time(), None
        while len(S["trades"]) > 40:
            old = min(S["trades"], key=lambda k: S["trades"][k]["fetched"])
            S["trades"].pop(old)


def trade_list(key):
    with LOCK:
        t = S["trades"].get(key)
        return sorted(t["rows"].values(), key=lambda r: -r["t"]) if t else []


def tracked_set(chain):
    return {w["addr"] if chain == "solana" else w["addr"].lower() for w in S["wallets"] if w["chain"] == chain}


def clusters_of(rows):
    rs = sorted([r for r in rows if r["usd"] >= 25], key=lambda r: r["t"])
    found, ex, skip = defaultdict(int), {}, -1
    for i, a in enumerate(rs):
        if a["t"] <= skip:
            continue
        grp = {}
        for b in rs[i:]:
            if b["t"] - a["t"] > 10:
                break
            if 0.85 * a["usd"] <= b["usd"] <= 1.15 * a["usd"]:
                grp.setdefault(b["wallet"], b)
        if len(grp) >= 3:
            k = frozenset(grp)
            found[k] += 1
            ex.setdefault(k, (a["t"], a["usd"]))
            skip = max(b["t"] for b in grp.values())
    out = [{"wallets": sorted(k)[:8], "n_wallets": len(k), "occurrences": n, "t": ex[k][0], "usd": ex[k][1]}
           for k, n in found.items() if n >= 2 or len(k) >= 4]
    return sorted(out, key=lambda x: (-x["occurrences"], -x["n_wallets"]))[:5]


def analyse_trades(c, rows):
    """Evidence-based activity analysis of REAL observed trades. Heuristics only: never proof of identity or intent."""
    if not rows:
        return None
    st = S["settings"]
    rows = sorted(rows, key=lambda r: r["t"])
    buys, sells = [r for r in rows if r["kind"] == "buy"], [r for r in rows if r["kind"] == "sell"]
    bu, su = sum(r["usd"] for r in buys), sum(r["usd"] for r in sells)
    thr_liq = c["liq"] * st["whale_liq_pct"] / 100.0 if c.get("liq") else None
    large = [r for r in rows if r["usd"] >= st["whale_usd"] or (thr_liq and r["usd"] >= thr_liq)]
    out = {"n": len(rows), "buy_n": len(buys), "sell_n": len(sells), "buy_usd": bu, "sell_usd": su, "net_usd": bu - su,
           "t0": rows[0]["t"], "t1": rows[-1]["t"], "whale_usd": st["whale_usd"], "whale_liq_usd": thr_liq,
           "large": sorted(large, key=lambda r: -r["usd"])[:15], "large_buy_usd": sum(r["usd"] for r in large if r["kind"] == "buy"),
           "large_sell_usd": sum(r["usd"] for r in large if r["kind"] == "sell"), "n_large": len(large)}
    byw = defaultdict(list)
    for r in rows:
        byw[r["wallet"]].append(r)
    total = bu + su
    tw = sorted(byw.items(), key=lambda kv: -sum(r["usd"] for r in kv[1]))[:5]
    out["top_wallets"] = [{"wallet": w, "n": len(rs), "usd": sum(r["usd"] for r in rs), "share_pct": 100.0 * sum(r["usd"] for r in rs) / total if total else 0,
                           "buy_usd": sum(r["usd"] for r in rs if r["kind"] == "buy"), "sell_usd": sum(r["usd"] for r in rs if r["kind"] == "sell")} for w, rs in tw]
    out["top3_share_pct"] = sum(x["share_pct"] for x in out["top_wallets"][:3])
    out["n_wallets"] = len(byw)
    sus = []
    for w, rs in byw.items():
        if len(rs) < 3:
            continue
        ts, us = [r["t"] for r in rs], [r["usd"] for r in rs]
        gaps = [b - a for a, b in zip(ts, ts[1:])]
        med, flags = (statistics.median(gaps) if gaps else None), []
        if len(rs) >= 8 and med is not None and med <= 20:
            flags.append("high frequency: %d trades, median gap %.0fs" % (len(rs), med))
        elif len(rs) >= 5 and ts[-1] - ts[0] <= 60:
            flags.append("burst: %d trades within %.0fs" % (len(rs), ts[-1] - ts[0]))
        mean = statistics.mean(us)
        if len(rs) >= 5 and mean > 0 and statistics.pstdev(us) / mean <= 0.15:
            flags.append("near-identical trade sizes (variation %.0f%%)" % (100 * statistics.pstdev(us) / mean))
        same = defaultdict(int)
        for t in ts:
            same[int(t)] += 1
        if max(same.values()) >= 3:
            flags.append("%d trades in the same second" % max(same.values()))
        b_, s_ = sum(r["usd"] for r in rs if r["kind"] == "buy"), sum(r["usd"] for r in rs if r["kind"] == "sell")
        if b_ > 0 and s_ > 0 and len(rs) >= 4 and ts[-1] - ts[0] <= 600 and min(b_, s_) / max(b_, s_) >= 0.8:
            flags.append("buys and sells of similar total size within %.0f min (round-tripping)" % ((ts[-1] - ts[0]) / 60))
        if len(flags) >= 2:
            sus.append({"wallet": w, "n": len(rs), "usd": sum(us), "flags": flags, "confidence": "medium" if len(flags) >= 3 else "low",
                        "label": "Suspected automated activity"})
    out["suspected"] = sorted(sus, key=lambda x: (-len(x["flags"]), -x["usd"]))[:8]
    out["cluster_buys"], out["cluster_sells"] = clusters_of(buys), clusters_of(sells)
    ts_ = tracked_set(c["chain"])
    out["tracked"] = [r for r in sorted(rows, key=lambda r: -r["t"]) if (r["wallet"] if c["chain"] == "solana" else r["wallet"].lower()) in ts_][:30]
    out["caveat"] = ("Wallet addresses are transaction signers/senders from public data. On EVM chains the sender can be a router or bot contract. "
                     "Flags are statistical patterns in at most the last 300 trades, not proof of automation, common ownership or intent.")
    return out


# ----------------------------------------------------------------------------- agents (deterministic Python; AI is separate)
def Fd(factor, obs, d, ev):
    return {"factor": factor, "obs": obs, "dir": d, "ev": ev}


def R(signal, summary, findings, used, missing, **kw):
    d = {"signal": signal, "summary": summary, "findings": findings, "used": used, "missing": missing}
    d.update(kw)
    return d


def sd(x):
    return "pos" if x >= 1 else "neg" if x <= -1 else "neu"


def local_series(h, secs=3600):
    return [p for p in h if p[0] >= time.time() - secs]


def fresh_ai(key):
    r = S["ai"]["coins"].get(key)
    return r if r and time.time() - r["analyzed_at"] <= S["settings"]["ai_max_age_min"] * 60 else None


def note_agent(name, r, ms):
    a = S["agents"].setdefault(name, {"runs": 0, "errors": 0, "last_run": 0, "last_ms": 0, "last_error": None, "status": "idle", "cerr": 0})
    a["runs"] += 1
    a["last_run"], a["last_ms"] = time.time(), ms
    if r.get("signal") == "error":
        a["errors"] += 1
        a["cerr"] += 1
        a["last_error"] = r.get("summary")


# ----------------------------------------------------------------------------- AI layer (real LLM calls only)


def ai_configured():
    return bool(secret("ai_key"))


def iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def ai_request(system, user_text):
    key, st = secret("ai_key"), S["settings"]
    if not key:
        raise ApiError("AI API NOT CONFIGURED", True)
    if st["ai_provider"] == "anthropic":
        url = AI_URL_OVERRIDE or "https://api.anthropic.com/v1/messages"
        out = http(P_AI, url, {"model": st["ai_model"], "max_tokens": 2200, "system": system, "messages": [{"role": "user", "content": user_text}]},
                   {"x-api-key": key, "anthropic-version": "2023-06-01"}, timeout=80, retries=2)
        try:
            return "".join(b.get("text", "") for b in out["content"] if isinstance(b, dict) and b.get("type") == "text")
        except (KeyError, TypeError):
            raise ApiError("AI provider returned an unexpected response format")
    url = AI_URL_OVERRIDE or st["ai_base"].rstrip("/") + "/chat/completions"
    out = http(P_AI, url, {"model": st["ai_model"], "temperature": 0.2, "messages": [{"role": "system", "content": system}, {"role": "user", "content": user_text}]},
               {"Authorization": "Bearer " + key}, timeout=80, retries=2)
    try:
        return out["choices"][0]["message"]["content"] or ""
    except (KeyError, IndexError, TypeError):
        raise ApiError("AI provider returned an unexpected response format")


def parse_ai_json(text):
    t = re.sub(r"^```(?:json)?\s*|\s*```$", "", (text or "").strip())
    a, b = t.find("{"), t.rfind("}")
    if a < 0 or b <= a:
        raise ApiError("AI reply contained no JSON object")
    try:
        o = json.loads(t[a:b + 1])
    except ValueError:
        raise ApiError("AI reply was not valid JSON")
    if not isinstance(o, dict):
        raise ApiError("AI reply JSON was not an object")
    return o


def _s(o, k, n=900, req=False):
    v = o.get(k)
    if not isinstance(v, str) or not v.strip():
        if req:
            raise ApiError("AI reply failed validation: '%s' missing" % k)
        return ""
    return v.strip()[:n]


def _l(o, k, req=False):
    v = o.get(k)
    if v is None and not req:
        return []
    if not isinstance(v, list) or not all(isinstance(x, (str, int, float)) for x in v):
        raise ApiError("AI reply failed validation: '%s' must be a list of strings" % k)
    out = [str(x).strip()[:350] for x in v if str(x).strip()][:8]
    if req and not out:
        raise ApiError("AI reply failed validation: '%s' is empty" % k)
    return out


def _enum(o, k, allowed):
    v = str(o.get(k, "")).strip().upper().replace("_", " ")
    for a in allowed:
        if v == a.upper():
            return a
    raise ApiError("AI reply failed validation: '%s' must be one of %s" % (k, ", ".join(allowed)))


def validate_market_ai(o):
    return {"conclusion": _enum(o, "conclusion", CONCL), "confidence": _enum(o, "confidence", ("low", "medium", "high")), "regime": _enum(o, "regime", ("bullish", "bearish", "sideways", "unclear")),
            "regime_reason": _s(o, "regime_reason", req=True), "bullish": _l(o, "bullish_evidence"), "bearish": _l(o, "bearish_evidence"), "risks": _l(o, "risks"),
            "missing": _l(o, "missing_information"), "uncertainty": _s(o, "uncertainty"), "reasons": _l(o, "reasons", True), "invalidation": _l(o, "invalidation_conditions", True)}


def tr_payload(tr):
    if not tr:
        return None
    short = lambda r: {"kind": r["kind"], "usd": round(r["usd"], 2), "wallet": r["wallet"][:6] + "…" + r["wallet"][-4:], "t_utc": iso(r["t"])}
    return {"observed_trades": tr["n"], "window_minutes": round((tr["t1"] - tr["t0"]) / 60, 1), "buy_usd": round(tr["buy_usd"]), "sell_usd": round(tr["sell_usd"]), "distinct_wallets": tr["n_wallets"],
            "top3_wallet_share_pct": round(tr["top3_share_pct"], 1), "large_trades": [short(r) for r in tr["large"][:8]],
            "suspected_automated_wallets": [{"wallet": x["wallet"][:6] + "…" + x["wallet"][-4:], "flags": x["flags"], "confidence": x["confidence"]} for x in tr["suspected"][:5]],
            "possible_coordinated_buying_clusters": len(tr["cluster_buys"]), "possible_coordinated_selling_clusters": len(tr["cluster_sells"]), "caveat": tr["caveat"]}


def run_ai(kind, key=None):
    if not ai_configured():
        raise ApiError("AI API NOT CONFIGURED", True)
    with LOCK:
        if kind == "coin":
            c = S["coins"].get(key)
            if not c:
                raise ApiError("Unknown coin: open it first", True)
            hit = S["ai"]["coins"].get(key)
            if hit and time.time() - hit["analyzed_at"] < 30:
                return hit
            payload, data_ts, sym, system = coin_payload(c), c["updated"], c["sym"], AI_SYSTEM_COIN
        else:
            o = S["overview"]
            if not o or o["n"] < 1:
                raise ApiError("No monitored market data yet", True)
            slim = lambda L: [{k: x[k] for k in ("sym", "chain", "h1", "h24", "liq", "ratio", "age_h")} for x in L]
            payload = {"task": "market_analysis", "data_source": "DexScreener public API; a sample of %d monitored tokens, NOT the whole market" % o["n"], "data_timestamp_utc": iso(o["ts"]),
                       "scope": {"tokens": o["n"], "chains": o["chains"]}, "breadth": {w: {"rising": o["rise_" + w], "falling": o["fall_" + w], "median_pct": o["med_" + w], "n": o["n_" + w]} for w in ("h1", "h6", "h24")},
                       "volume_last_hour_vs_24h_hourly_average": o["vol_ratio"], "median_liquidity_change_pct_recent": o["liq_chg_med"], "software_regime": o["regime"],
                       "top_gainers_1h": slim(o["gain_h1"]), "top_losers_1h": slim(o["lose_h1"]), "unusual_volume": slim(o["unusual"]), "new_pairs_under_24h": slim(o["new"]),
                       "notes": ["null means unavailable", "discovery lists are boosted/profile tokens: a biased sample"]}
            data_ts, sym, system = o["ts"], "MARKET", AI_SYSTEM_MARKET
        S["ai"]["busy"] = True
    t0 = time.time()
    try:
        raw = parse_ai_json(ai_request(system, json.dumps(clean(payload))))
        out = validate_coin_ai(raw) if kind == "coin" else validate_market_ai(raw)
    except ApiError as e:
        with LOCK:
            a = S["agents"].setdefault("ai", {"runs": 0, "errors": 0, "last_run": 0, "last_ms": 0, "last_error": None, "status": "idle", "cerr": 0})
            a["errors"] += 1
            a["last_error"] = scrub(e)
            S["ai"]["error"] = scrub(e)
        bump()
        raise
    finally:
        with LOCK:
            S["ai"]["busy"] = False
    ms = int((time.time() - t0) * 1000)
    with LOCK:
        S["ai"]["seq"] += 1
        out.update(id=S["ai"]["seq"], kind=kind, key=key, sym=sym, analyzed_at=time.time(), data_ts=data_ts, ms=ms, provider=S["settings"]["ai_provider"], model=S["settings"]["ai_model"])
        S["ai"]["error"] = None
        if kind == "coin":
            S["ai"]["coins"][key] = out
            if key in S["coins"]:
                S["coins"][key]["analysis"] = analyse(S["coins"][key])
        S["ai"]["history"].insert(0, out)
        del S["ai"]["history"][12:]
        a = S["agents"].setdefault("ai", {"runs": 0, "errors": 0, "last_run": 0, "last_ms": 0, "last_error": None, "status": "idle", "cerr": 0})
        a.update(runs=a["runs"] + 1, last_run=time.time(), last_ms=ms)
    bump()
    return out


# ----------------------------------------------------------------------------- market overview
def compute_overview():
    st, now = S["settings"], time.time()
    lim = max(90, 3 * st["refresh_s"])
    cs = [c for c in S["coins"].values() if c.get("mon") and now - c["updated"] <= lim]
    o = {"n": len(cs), "ts": now, "chains": {}, "pump_n": sum(1 for c in cs if pump_info(c))}
    for c in cs:
        o["chains"][c["chain"]] = o["chains"].get(c["chain"], 0) + 1
    med = lambda a: statistics.median(a) if a else None
    for w in ("h1", "h6", "h24"):
        v = [c["chg"][w] for c in cs if c["chg"].get(w) is not None]
        o["rise_" + w], o["fall_" + w], o["n_" + w], o["med_" + w] = sum(1 for x in v if x > 0), sum(1 for x in v if x < 0), len(v), med(v)
    both = [c for c in cs if c["vol"].get("h1") is not None and c["vol"].get("h24")]
    o["vol24"] = sum(c["vol"]["h24"] for c in cs if c["vol"].get("h24") is not None)
    o["liq"] = sum(c["liq"] for c in cs if c["liq"] is not None)
    s1, s24 = sum(c["vol"]["h1"] for c in both), sum(c["vol"]["h24"] for c in both)
    o["vol_ratio"] = (s1 / (s24 / 24.0)) if s24 > 0 else None
    chg = []
    for c in cs:
        pts = [p for p in S["hist"].get(c["key"], []) if p[0] >= now - 3600 and p[2]]
        if len(pts) >= 2 and pts[-1][0] - pts[0][0] >= 600:
            chg.append(100.0 * (pts[-1][2] / pts[0][2] - 1))
    o["liq_chg_med"], o["liq_chg_n"] = med(chg), len(chg)
    if o["n_h1"] < 8:
        o["regime"], o["why"] = "insufficient", "Only %d monitored tokens have 1h data; at least 8 are needed for a momentum reading." % o["n_h1"]
    else:
        share, m1, m6 = o["rise_h1"] / o["n_h1"], o["med_h1"], o["med_h6"]
        o["regime"] = "bullish" if (share >= 0.6 and m1 > 0.3 and (m6 is None or m6 > 0)) else "bearish" if (share <= 0.4 and m1 < -0.3 and (m6 is None or m6 < 0)) else "sideways"
        o["why"] = "%d of %d monitored tokens are up over 1h; median 1h move %+.1f%%." % (o["rise_h1"], o["n_h1"], m1)

    def mini(c):
        a = c.get("analysis") or {}
        return {"key": c["key"], "sym": c["sym"], "chain": c["chain"], "price": c["price"], "h1": c["chg"].get("h1"), "h24": c["chg"].get("h24"), "liq": c["liq"],
                "ratio": (a.get("volume") or {}).get("ratio"), "age_h": age_h(c), "concl": (a.get("consensus") or {}).get("conclusion")}
    by = lambda w, rev: sorted([c for c in cs if c["chg"].get(w) is not None], key=lambda c: c["chg"][w], reverse=rev)[:5]
    o["gain_h1"], o["lose_h1"] = [mini(c) for c in by("h1", True)], [mini(c) for c in by("h1", False)]
    o["gain_h24"], o["lose_h24"] = [mini(c) for c in by("h24", True)], [mini(c) for c in by("h24", False)]
    o["unusual"] = [mini(c) for c in sorted([c for c in cs if (c["analysis"]["volume"] or {}).get("unusual")], key=lambda c: -c["analysis"]["volume"]["ratio"])[:5]]
    o["new"] = [mini(c) for c in sorted([c for c in cs if age_h(c) is not None and age_h(c) < 24], key=age_h)[:5]]
    S["overview"] = o


# ----------------------------------------------------------------------------- candles and calculated technical indicators
S.setdefault("alerts", [])
S.setdefault("alert_seen", {})
S.setdefault("candles", {})
TFS = {"1m": ("minute", 1, 120), "5m": ("minute", 5, 120), "15m": ("minute", 15, 120), "1h": ("hour", 1, 120), "4h": ("hour", 4, 120), "1D": ("day", 1, 90)}


def get_candles(c, tf, max_age=60):
    """Source-provided OHLCV from the documented GeckoTerminal/CoinGecko on-chain OHLCV endpoint."""
    net = GT_NET.get(c["chain"])
    if tf not in TFS:
        raise ApiError("Unknown timeframe", True)
    if not net or not c.get("pair") or not PATH_ID.match(c["pair"]):
        raise ApiError("OHLCV candles are not available for this chain/pool from the connected provider", True)
    ck = (c["key"], tf)
    with LOCK:
        hit = S["candles"].get(ck)
    if hit and time.time() - hit[0] < max_age:
        return hit[1]
    unit, agg, lim = TFS[tf]
    data = gt_get("/networks/%s/pools/%s/ohlcv/%s?aggregate=%d&limit=%d&currency=usd&token=%s" % (net, c["pair"], unit, agg, lim, c["addr"]))
    try:
        rows = data["data"]["attributes"]["ohlcv_list"]
    except (KeyError, TypeError):
        raise ApiError("GeckoTerminal: unexpected candle response format")
    out = []
    for r in rows if isinstance(rows, list) else []:
        if isinstance(r, list) and len(r) >= 6 and all(fnum(x) is not None for x in r[:6]):
            o, h_, l_, cl, v = (float(x) for x in r[1:6])
            if min(o, h_, l_, cl) > 0 and h_ >= l_ and v >= 0:
                out.append([float(r[0]), o, h_, l_, cl, v])
    out.sort()
    with LOCK:
        S["candles"][ck] = (time.time(), out)
        while len(S["candles"]) > 80:
            S["candles"].pop(min(S["candles"], key=lambda k: S["candles"][k][0]))
    return out


def sma(v, n):
    out, s = [None] * len(v), 0.0
    for i, x in enumerate(v):
        s += x
        if i >= n:
            s -= v[i - n]
        if i >= n - 1:
            out[i] = s / n
    return out


def ema(v, n):
    out, k, e = [None] * len(v), 2.0 / (n + 1), None
    for i, x in enumerate(v):
        if i < n - 1:
            continue
        e = sum(v[:n]) / n if i == n - 1 else x * k + e * (1 - k)
        out[i] = e
    return out


def rsi(v, n=14):
    out = [None] * len(v)
    if len(v) <= n:
        return out
    g = [max(v[i] - v[i - 1], 0) for i in range(1, len(v))]
    l_ = [max(v[i - 1] - v[i], 0) for i in range(1, len(v))]
    ag, al = sum(g[:n]) / n, sum(l_[:n]) / n
    out[n] = 100.0 if al == 0 else 100 - 100 / (1 + ag / al)
    for i in range(n + 1, len(v)):
        ag, al = (ag * (n - 1) + g[i - 1]) / n, (al * (n - 1) + l_[i - 1]) / n
        out[i] = 100.0 if al == 0 else 100 - 100 / (1 + ag / al)
    return out


def macd(v):
    e12, e26 = ema(v, 12), ema(v, 26)
    line = [(a - b) if a is not None and b is not None else None for a, b in zip(e12, e26)]
    idx = [i for i, x in enumerate(line) if x is not None]
    sig, hist = [None] * len(v), [None] * len(v)
    if len(idx) >= 9:
        s = ema([line[i] for i in idx], 9)
        for j, i in enumerate(idx):
            sig[i] = s[j]
            hist[i] = None if s[j] is None else line[i] - s[j]
    return line, sig, hist


def tech_analysis(rows):
    """Indicators CALCULATED by this app from provider candles (not provider-supplied)."""
    n = len(rows)
    if n < 20:
        return None
    cl, hi, lo, vo = [r[4] for r in rows], [r[2] for r in rows], [r[3] for r in rows], [r[5] for r in rows]
    e20, s50, rs = ema(cl, 20), sma(cl, 50), rsi(cl, 14)
    ml, ms, mh = macd(cl)
    sigs = []

    def add(kind, d, text):
        sigs.append({"type": kind, "dir": d, "text": text, "t": rows[-1][0]})
    pv, ph, pl = vo[-21:-1], hi[-21:-1], lo[-21:-1]
    avgv = sum(pv) / len(pv) if pv and sum(pv) > 0 else None
    vx = vo[-1] / avgv if avgv else None
    if cl[-1] > max(ph):
        add("breakout", "pos" if vx and vx >= 1.5 else "neu", "Close is above the previous 20-candle high (%s). %s" % (fmt_px(max(ph)), "Confirmed by volume %.1fx average." % vx if vx and vx >= 1.5 else "NOT confirmed by volume (%s): breakouts without volume fail often." % ("%.1fx average" % vx if vx else "volume unavailable")))
    elif cl[-1] < min(pl):
        add("breakdown", "neg" if vx and vx >= 1.5 else "neu", "Close is below the previous 20-candle low (%s). %s" % (fmt_px(min(pl)), "Volume %.1fx average confirms the selling." % vx if vx and vx >= 1.5 else "Volume does not confirm."))
    if vx and vx >= 3:
        add("volume_spike", "neu", "Latest candle volume is %.1fx its 20-candle average (spike: direction depends on the candle)." % vx)
    rng = [h_ - l_ for h_, l_ in zip(hi, lo)]
    ar = sum(rng[-21:-1]) / 20.0
    if ar > 0 and rng[-1] >= 3 * ar:
        add("abnormal_candle", "neu", "Latest candle range is %.1fx the 20-candle average range (abnormal)." % (rng[-1] / ar))
    if rs[-1] is not None:
        if rs[-1] >= 70:
            add("rsi", "neg", "RSI(14) = %.0f: overbought zone (stretched, can precede pullbacks; not a signal alone)." % rs[-1])
        elif rs[-1] <= 30:
            add("rsi", "neu", "RSI(14) = %.0f: oversold zone (falling hard; not a buy signal alone)." % rs[-1])
        else:
            add("rsi", "neu", "RSI(14) = %.0f: neutral zone." % rs[-1])
    hs = [x for x in mh[-4:] if x is not None]
    if len(hs) >= 2 and hs[-1] * hs[0] < 0:
        add("macd_cross", "pos" if hs[-1] > 0 else "neg", "MACD histogram crossed %s zero within the last 3 candles." % ("above" if hs[-1] > 0 else "below"))
    elif hs:
        add("macd", "pos" if hs[-1] > 0 else "neg", "MACD histogram is %s zero." % ("above" if hs[-1] > 0 else "below"))
    if e20[-1] is not None:
        add("ema", "pos" if cl[-1] > e20[-1] else "neg", "Close is %s the EMA(20) (%s)." % ("above" if cl[-1] > e20[-1] else "below", fmt_px(e20[-1])))
    if e20[-1] is not None and s50[-1] is not None:
        add("ma_cross", "pos" if e20[-1] > s50[-1] else "neg", "EMA(20) is %s SMA(50)." % ("above" if e20[-1] > s50[-1] else "below"))
    sup, res = [], []
    if n >= 30:
        piv = []
        for i in range(3, n - 3):
            if lo[i] == min(lo[i - 3:i + 4]):
                piv.append(("s", lo[i]))
            if hi[i] == max(hi[i - 3:i + 4]):
                piv.append(("r", hi[i]))
        last = cl[-1]
        for side in ("s", "r"):
            lv = sorted(p for k, p in piv if k == side)
            groups = []
            for p in lv:
                if groups and abs(p / groups[-1][-1] - 1) <= 0.015:
                    groups[-1].append(p)
                else:
                    groups.append([p])
            est = [{"level": sum(g) / len(g), "touches": len(g)} for g in groups]
            if side == "s":
                sup = sorted([e for e in est if e["level"] < last], key=lambda e: -e["level"])[:3]
            else:
                res = sorted([e for e in est if e["level"] > last], key=lambda e: e["level"])[:3]
    return {"n": n, "ema20": e20, "sma50": s50, "rsi14": rs, "macd": ml, "macd_signal": ms, "macd_hist": mh, "signals": sigs, "support": sup, "resistance": res,
            "vol_x": vx, "note": "Candles are source-provided (GeckoTerminal). EMA, SMA, RSI, MACD, breakout, spike and support/resistance values are CALCULATED by this app. Support/resistance are rough swing-point estimates, not guarantees."}


def fmt_px(p):
    return "%.6g" % p


def cached_tech(key):
    with LOCK:
        hit = S["candles"].get((key, "15m"))
    if hit and time.time() - hit[0] < 900:
        t = tech_analysis(hit[1])
        if t:
            t["fetched"], t["tf"] = hit[0], "15m"
        return t
    return None


# ----------------------------------------------------------------------------- alerts
def add_alert(kind, c, text, dedupe="", ttl=3600, ev=None):
    now, sig = time.time(), (kind, c["key"], dedupe)
    with LOCK:
        if now - S["alert_seen"].get(sig, 0) < ttl:
            return False
        S["alert_seen"][sig] = now
        if len(S["alert_seen"]) > 800:
            for k in sorted(S["alert_seen"], key=S["alert_seen"].get)[:300]:
                S["alert_seen"].pop(k)
        S["alerts"].insert(0, {"t": now, "kind": kind, "key": c["key"], "sym": c["sym"], "chain": c["chain"], "text": text[:300], "ev": ev})
        del S["alerts"][150:]
    return True


def scan_alerts(c):
    a = c.get("analysis") or {}
    if (a.get("volume") or {}).get("unusual"):
        add_alert("volume", c, "Unusual volume: last hour is %.1fx the 24h hourly average" % a["volume"]["ratio"], "spike", 1800)
    for f in (a.get("liquidity") or {}).get("findings", []):
        if f["factor"].startswith("Liquidity change") and f["dir"] == "neg":
            add_alert("liquidity", c, "Liquidity dropped: " + f["obs"], "drop", 1800)
    b = a.get("bot") or {}
    if b.get("signal") == "bearish":
        add_alert("bot", c, "Suspected automated or manipulative patterns: " + "; ".join(x["factor"] for x in b["findings"] if x["dir"] == "neg")[:200], "bot", 3600)


def ingest_trades(c, rows):
    """Store real trades and raise alerts for NEW large trades and tracked-wallet activity."""
    st = S["settings"]
    with LOCK:
        old = S["trades"].get(c["key"], {}).get("rows", {})
        seen = set(old)
        first = not old
    store_trades(c["key"], rows)
    if first:
        return
    thr_liq = c["liq"] * st["whale_liq_pct"] / 100.0 if c.get("liq") else None
    tset = tracked_set(c["chain"])
    n = 0
    for r in sorted(rows, key=lambda r: -r["usd"]):
        if (r["tx"], r["kind"], round(r["usd"], 4)) in seen:
            continue
        w = r["wallet"] if c["chain"] == "solana" else r["wallet"].lower()
        if w in tset:
            add_alert("tracked", c, "Tracked wallet %s…%s %s $%s of %s" % (r["wallet"][:5], r["wallet"][-4:], r["kind"], format(int(r["usd"]), ","), c["sym"]), r["tx"], 86400,
                      {"tx": r["tx"], "wallet": r["wallet"]})
        elif (r["usd"] >= st["whale_usd"] or (thr_liq and r["usd"] >= thr_liq)) and n < 5:
            n += 1
            add_alert("whale", c, "Large %s: $%s of %s from %s…%s" % (r["kind"], format(int(r["usd"]), ","), c["sym"], r["wallet"][:5], r["wallet"][-4:]), r["tx"], 86400,
                      {"tx": r["tx"], "wallet": r["wallet"]})


# ----------------------------------------------------------------------------- agents (deterministic Python; the AI agent is separate)
def agent_trend(c, h, tr, tc):
    chg, f, used, missing = c["chg"], [], [], []
    for w, lab in (("m5", "5 minutes"), ("h1", "1 hour"), ("h6", "6 hours"), ("h24", "24 hours")):
        v = chg.get(w)
        if v is None:
            missing.append("priceChange." + w)
            continue
        used.append("priceChange." + w)
        f.append(Fd("Price change, " + lab, "%+.1f%%" % v, sd(v), "DexScreener priceChange." + w))
    if chg.get("h1") is None or len(f) < 2:
        return R("no_data", "Too few price-change fields to judge a trend.", f, used, missing)
    if chg.get("m5") is not None:
        pace = chg["h1"] / 12.0
        if chg["m5"] > 0 and chg["m5"] > pace * 1.5 and chg["h1"] > 0:
            f.append(Fd("Momentum", "Last 5 minutes (%+.1f%%) is faster than the 1h average pace (%+.1f%% per 5m)" % (chg["m5"], pace), "pos", "derived from m5 and h1"))
        elif chg["m5"] < 0 < chg["h1"]:
            f.append(Fd("Momentum", "Fading: last 5 minutes %+.1f%% while the 1h change is %+.1f%%" % (chg["m5"], chg["h1"]), "neg", "derived from m5 and h1"))
        else:
            f.append(Fd("Momentum", "No clear acceleration or fade between 5m and 1h", "neu", "derived from m5 and h1"))
    if chg.get("h24") is not None and chg["h24"] > 300:
        f.append(Fd("Extended move", "%+.0f%% in 24h: late entries carry elevated reversal risk" % chg["h24"], "neg", "DexScreener priceChange.h24"))
    pts = local_series(h, 7200)
    if len(pts) >= 10:
        rets = [100.0 * (b[1] / a[1] - 1) for a, b in zip(pts, pts[1:]) if a[1] > 0]
        if len(rets) >= 5:
            vol = statistics.pstdev(rets)
            used.append("locally collected snapshots (%d)" % len(pts))
            f.append(Fd("Volatility (locally collected)", "%.2f%% standard deviation per snapshot over %d snapshots" % (vol, len(pts)), "neg" if vol > 3 else "neu", "this app's own snapshots, not exchange history"))
    else:
        missing.append("local volatility (needs 10+ snapshots collected by this app)")
    if tc:
        used.append("calculated indicators from %d 15m candles" % tc["n"])
        for s in tc["signals"]:
            if s["type"] in ("ema", "ma_cross", "macd", "macd_cross", "rsi", "breakout", "breakdown"):
                f.append(Fd({"ema": "EMA(20)", "ma_cross": "EMA/SMA", "macd": "MACD", "macd_cross": "MACD cross", "rsi": "RSI(14)", "breakout": "Breakout", "breakdown": "Breakdown"}[s["type"]], s["text"], s["dir"], "calculated from GeckoTerminal 15m OHLCV"))
    else:
        missing.append("candle indicators (open Candlestick Analysis or watch the coin to fetch 15m candles)")
    ds = [x["dir"] for x in f]
    pos, neg = ds.count("pos"), ds.count("neg")
    sig = "bullish" if pos > neg + 1 and pos >= 3 else "bearish" if neg > pos + 1 and neg >= 3 else "neutral"
    return R(sig, "%d supporting and %d negative factors among %d (price windows and, if available, calculated indicators)." % (pos, neg, len(ds)), f, used, missing)


def agent_volume(c, h, tr, tc):
    v, f, used, missing = c["vol"], [], [], []
    v1, v24, v5 = v.get("h1"), v.get("h24"), v.get("m5")
    if v1 is None or v24 is None or v24 <= 0:
        return R("no_data", "1h and 24h volume are both needed.", f, used, ["volume.h1", "volume.h24"])
    used += ["volume.h1", "volume.h24"]
    base = v24 / 24.0
    ratio = v1 / base
    kind = "spike" if ratio >= 3 else "expanded" if ratio >= 1.5 else "dry" if ratio < 0.5 else "normal"
    f.append(Fd("Volume expansion", "Last hour is %.1fx the 24h hourly average (%s). Baseline = 24h volume / 24, which includes the last hour." % (ratio, kind),
                "pos" if kind in ("spike", "expanded") else "neg" if kind == "dry" else "neu", "DexScreener volume.h1 and volume.h24"))
    if v5 is not None:
        used.append("volume.m5")
        f.append(Fd("Short-term pace", "5-minute volume pace is %.1fx baseline" % (v5 * 12 / base), "neu", "DexScreener volume.m5"))
    else:
        missing.append("volume.m5")
    liq = c["liq"]
    if liq:
        used.append("liquidity.usd")
        ch = v24 / liq
        f.append(Fd("Volume quality: churn", "24h volume is %.1fx liquidity%s" % (ch, " (heavy churn: can indicate wash trading or hype)" if ch > 20 else ""), "neg" if ch > 20 else "neu", "volume.h24 / liquidity.usd"))
    t1 = c["tx"].get("h1") or {}
    b, s = t1.get("buys"), t1.get("sells")
    bs = None
    if b is not None and s is not None and b + s > 0:
        used.append("txns.h1")
        bs = b / (b + s)
        f.append(Fd("Buy/sell pressure", "%d transactions in 1h (%.0f%% buys), average about $%.0f each. Provider gives counts, not buy/sell dollar volume." % (b + s, bs * 100, (v1 / (b + s)) if v1 else 0), "pos" if bs >= 0.55 else "neg" if bs <= 0.45 else "neu", "DexScreener txns.h1 (counts, not unique wallets)"))
    else:
        missing.append("txns.h1")
    if tr:
        used.append("observed trades")
        tot = tr["buy_usd"] + tr["sell_usd"]
        if tot > 0:
            f.append(Fd("Observed buy/sell dollar volume", "Buys %.0f%% of $%s observed over %.0f min" % (100 * tr["buy_usd"] / tot, format(int(tot), ","), (tr["t1"] - tr["t0"]) / 60), "pos" if tr["buy_usd"] > tr["sell_usd"] * 1.15 else "neg" if tr["sell_usd"] > tr["buy_usd"] * 1.15 else "neu", "GeckoTerminal pool trades (USD per trade is the provider's estimate)"))
    if tc:
        used.append("calculated candle volume")
        for s_ in tc["signals"]:
            if s_["type"] == "volume_spike":
                f.append(Fd("Spike candle", s_["text"], "neu", "calculated from 15m OHLCV"))
    h1c = c["chg"].get("h1")
    sig = "neutral"
    if kind in ("spike", "expanded") and h1c is not None and h1c >= 1 and (bs is None or bs >= 0.5):
        sig = "bullish"
    elif kind in ("spike", "expanded") and ((h1c is not None and h1c <= -1) or (bs is not None and bs <= 0.45)):
        sig = "bearish"
    return R(sig, "Volume is %s versus its 24h baseline." % kind, f, used, missing, ratio=round(ratio, 2), unusual=ratio >= 3)


def agent_risk(c, h, tr, tc):
    st, used, missing, items, hard = S["settings"], [], [], [], []

    def add(p, item, why):
        items.append({"item": item, "points": p, "why": why})
    liq, a = c["liq"], age_h(c)
    if liq is None:
        add(25, "Liquidity unknown", "No liquidity value reported")
        missing.append("liquidity.usd")
    else:
        used.append("liquidity.usd")
        p = 35 if liq < 25e3 else 20 if liq < 1e5 else 8 if liq < 2.5e5 else 0
        if p:
            add(p, "Thin liquidity", "$%s: exits may be costly" % format(int(liq), ","))
    if a is None:
        add(10, "Pair age unknown", "No creation time reported")
        missing.append("pairCreatedAt")
    else:
        used.append("pairCreatedAt")
        p = 30 if a < 6 else 20 if a < 24 else 8 if a < 72 else 0
        if p:
            add(p, "Very new pair", "%.1f hours old: most rug pulls happen early" % a)
    if c["fdv"] and liq and liq / c["fdv"] < 0.01:
        add(15, "Liquidity under 1% of FDV", "%.2f%%" % (100 * liq / c["fdv"]))
    v24 = c["vol"].get("h24")
    if v24 is not None and liq and v24 / liq > 20:
        add(10, "Heavy volume churn", "24h volume is %.0fx liquidity" % (v24 / liq))
    t1 = c["tx"].get("h1") or {}
    b, s = t1.get("buys"), t1.get("sells")
    if b is not None and s is not None and b + s >= 20:
        used.append("txns.h1")
        if b and s / b > 1.3:
            add(12, "Sell pressure", "Sells outnumber buys by %.0f%% in the last hour" % (100 * (s / b - 1)))
    else:
        missing.append("txns.h1 (needs 20+ transactions)")
    if c["chg"].get("h24") is not None and abs(c["chg"]["h24"]) > 300:
        add(8, "Extreme 24h move", "%+.0f%%" % c["chg"]["h24"])
    with LOCK:
        oc = S["onchain"].get(c["key"])
    if oc and time.time() - oc["fetched"] < 3600:
        used.append("holder concentration (Solana RPC)")
        p = 20 if oc["top10_pct"] > 50 else 10 if oc["top10_pct"] > 30 else 0
        if p:
            add(p, "Concentrated token accounts", "Top 10 hold %.0f%% (may include pool vaults)" % oc["top10_pct"])
    else:
        missing.append("holder concentration (Solana only: use 'Holder check')")
    if tr:
        used.append("observed transactions (%d)" % tr["n"])
        if len(tr["suspected"]) >= 2:
            add(8, "Several wallets with automated-looking patterns", "%d wallets matched 2+ statistical flags" % len(tr["suspected"]))
        if tr["cluster_buys"] or tr["cluster_sells"]:
            add(10, "Possible coordinated activity", "Tight-timing, similar-size trades from 3+ wallets, repeated")
        if tr["top3_share_pct"] > 50 and tr["n_wallets"] >= 5:
            add(8, "Volume concentrated in few wallets", "Top 3 wallets = %.0f%% of observed volume" % tr["top3_share_pct"])
    else:
        missing.append("transaction-pattern checks (fetch transactions first)")
    missing += ["contract checks: mint/freeze authority, honeypot or sell-tax simulation, LP lock or burn, creator history (need a contract-analysis provider, not connected)"]
    total = min(100, sum(i["points"] for i in items))
    if total >= 60:
        hard.append("risk checklist tally is %d (60 or more)" % total)
    if liq is None or liq < st["min_liq"]:
        hard.append("liquidity below your minimum of $%s" % format(int(st["min_liq"]), ","))
    if a is None and st["min_age_h"] > 0:
        hard.append("pair age unknown")
    elif a is not None and a < st["min_age_h"]:
        hard.append("pair younger than your minimum of %.1f hours" % st["min_age_h"])
    level = "low" if total < 30 else "medium" if total < 55 else "high"
    f = [Fd(i["item"], "%s (+%d)" % (i["why"], i["points"]), "neg", "risk checklist") for i in items] or [Fd("No checklist item triggered", "None of the checkable indicators fired. Unchecked risks remain (see missing information).", "pos", "risk checklist")]
    return R("bearish" if hard else "neutral", "Risk checklist tally %d of 100 (%s). The tally adds fixed points per indicator that fired; it is not a probability of loss or of a rug pull." % (total, level),
             f, used, missing, risk=total, level=level, hard=hard, items=items)


def agent_bot(c, h, tr, tc):
    """Suspected automated / manipulative patterns. Statistical heuristics on observable data; never proof of a bot."""
    f, used, missing = [], [], []
    liq, v = c["liq"], c["vol"]
    if liq and v.get("h24") and v["h24"] / liq > 20:
        f.append(Fd("Possible wash-trading indicator", "24h volume is %.0fx liquidity: heavy churn relative to the pool's size" % (v["h24"] / liq), "neg", "DexScreener volume.h24 / liquidity.usd"))
    h1c = c["chg"].get("h1")
    if h1c is not None and abs(h1c) >= 10 and liq and v.get("h1") is not None and v["h1"] / liq < 0.02:
        f.append(Fd("Price move inconsistent with volume", "Price moved %+.1f%% in 1h on only $%s volume (%.1f%% of liquidity)" % (h1c, format(int(v["h1"]), ","), 100 * v["h1"] / liq), "neg", "priceChange.h1 vs volume.h1 and liquidity.usd"))
    pts = [x for x in h if x[0] >= time.time() - 3600 and x[2]]
    if len(pts) >= 3 and pts[-1][0] - pts[0][0] >= 600:
        used.append("locally collected liquidity snapshots")
        lc = 100.0 * (pts[-1][2] / pts[0][2] - 1)
        if lc <= -20 or lc >= 50:
            f.append(Fd("Suspicious liquidity change", "Liquidity changed %+.0f%% over %.0f min (locally collected)" % (lc, (pts[-1][0] - pts[0][0]) / 60), "neg", "this app's snapshots"))
    else:
        missing.append("liquidity change history (needs 10+ minutes of local snapshots)")
    if not tr:
        missing.append("transaction-level patterns: repeated sizes, high frequency, round trips, clustering, coordinated wallets (fetch transactions)")
        sig = "bearish" if len(f) >= 2 else "no_data" if not f else "neutral"
        return R(sig, "Only snapshot-based indicators could be checked; no transaction data has been fetched for this coin.", f, used, missing, partial=True)
    used.append("observed trades (%d over %.0f min)" % (tr["n"], (tr["t1"] - tr["t0"]) / 60))
    for s in tr["suspected"][:3]:
        f.append(Fd("Suspected automated pattern", "Wallet %s…%s: %s" % (s["wallet"][:5], s["wallet"][-4:], "; ".join(s["flags"])), "neg", "observed trades; confidence %s; not proof" % s["confidence"]))
    for k, lab in (("cluster_buys", "buying"), ("cluster_sells", "selling")):
        for cl in tr[k][:2]:
            f.append(Fd("Possible coordinated " + lab, "%d wallets traded similar sizes (~$%s) within 10 seconds, %d time(s)" % (cl["n_wallets"], format(int(cl["usd"]), ","), cl["occurrences"]), "neg", "observed trades; common ownership cannot be established"))
    rows = trade_list(c["key"])
    if len(rows) >= 20:
        cnt = defaultdict(int)
        for r in rows:
            if r["usd"] >= 25:
                cnt[round(r["usd"])] += 1
        if cnt:
            sz, n = max(cnt.items(), key=lambda kv: kv[1])
            if n >= 6 and n >= 0.15 * len(rows):
                f.append(Fd("Repeated identical trade size", "%d of %d trades are about $%s" % (n, len(rows), format(sz, ",")), "neg", "observed trades"))
        ts = sorted(r["t"] for r in rows)
        best, j = 0, 0
        for i in range(len(ts)):
            while ts[i] - ts[j] > 10:
                j += 1
            best = max(best, i - j + 1)
        if best >= 8 and best >= 0.2 * len(ts):
            f.append(Fd("Transaction clustering", "%d trades landed inside one 10-second window (%.0f%% of observed trades)" % (best, 100.0 * best / len(ts)), "neg", "observed trades"))
        mid = (ts[0] + ts[-1]) / 2
        a1 = [r for r in rows if r["t"] <= mid]
        a2 = [r for r in rows if r["t"] > mid]
        if len(a1) >= 8 and len(a2) >= 8:
            s1 = sum(1 for r in a1 if r["kind"] == "buy") / len(a1)
            s2 = sum(1 for r in a2 if r["kind"] == "buy") / len(a2)
            if abs(s2 - s1) >= 0.2:
                f.append(Fd("Buy/sell pressure shift", "Buy share moved from %.0f%% to %.0f%% between the first and second half of the window" % (100 * s1, 100 * s2), "pos" if s2 > s1 else "neg", "observed trades"))
        tot = tr["buy_usd"] + tr["sell_usd"]
        if h1c is not None and h1c >= 5 and tot > 0 and tr["net_usd"] < -0.2 * tot:
            f.append(Fd("Price up but observed flow is selling", "1h price %+.1f%% while observed net flow is -$%s" % (h1c, format(int(-tr["net_usd"]), ",")), "neg", "priceChange.h1 vs observed trades"))
    negcats = sum(1 for x in f if x["dir"] == "neg")
    if not f:
        f.append(Fd("No pattern flagged", "None of the implemented heuristics fired in the observed window", "pos", "observed trades"))
    sig = "bearish" if negcats >= 2 else "neutral"
    return R(sig, "%d indicator(s) fired in %d observed trades over %.0f minutes (%s). Findings are statistical patterns, labelled 'suspected', never proof of automation." % (negcats, tr["n"], (tr["t1"] - tr["t0"]) / 60, "GeckoTerminal pool trades"),
             f, used, missing)


def agent_whale(c, h, tr, tc):
    if not tr or tr["n"] < 10:
        return R("no_data", "Fewer than 10 observed transactions. Fetch transactions for this coin (Live Transactions tab) to enable wallet analysis.", [], [], ["transactions (GeckoTerminal pool trades)"])
    f = []
    thr = "$%s" % format(int(tr["whale_usd"]), ",") + (" or $%s (%.1f%% of liquidity)" % (format(int(tr["whale_liq_usd"]), ","), S["settings"]["whale_liq_pct"]) if tr["whale_liq_usd"] else "")
    f.append(Fd("Large trades", "%d at or above %s: large buys $%s, large sells $%s" % (tr["n_large"], thr, format(int(tr["large_buy_usd"]), ","), format(int(tr["large_sell_usd"]), ",")),
                "pos" if tr["large_buy_usd"] > 1.5 * tr["large_sell_usd"] and tr["large_buy_usd"] > 0 else "neg" if tr["large_sell_usd"] > 1.5 * tr["large_buy_usd"] and tr["large_sell_usd"] > 0 else "neu", "your whale threshold in Settings"))
    f.append(Fd("Net observed flow", "Net %s$%s over %.0f minutes" % ("+" if tr["net_usd"] >= 0 else "-", format(int(abs(tr["net_usd"])), ","), (tr["t1"] - tr["t0"]) / 60), "pos" if tr["net_usd"] > 0 else "neg", "GeckoTerminal pool trades"))
    f.append(Fd("Concentration", "%d distinct wallets; top 3 account for %.0f%% of observed volume" % (tr["n_wallets"], tr["top3_share_pct"]), "neg" if tr["top3_share_pct"] > 50 and tr["n_wallets"] >= 5 else "neu", "observed trades"))
    if tr["tracked"]:
        f.append(Fd("Tracked wallets", "%d trade(s) from wallets on your tracked list" % len(tr["tracked"]), "neu", "your wallet watchlist"))
    sig = "bullish" if f[0]["dir"] == "pos" and tr["net_usd"] > 0 else "bearish" if f[0]["dir"] == "neg" and tr["net_usd"] < 0 else "neutral"
    return R(sig, "Covers only the last %d observed trades. No wallet is labelled 'smart money': that needs verified historical performance, which this app does not compute." % tr["n"], f,
             ["GeckoTerminal pool trades (%d)" % tr["n"]], ["wallet funding history, labels and past performance (not available)"])


def agent_liquidity(c, h, tr, tc):
    liq, f, used, missing = c["liq"], [], [], []
    p = pump_info(c)
    if liq is None:
        return R("no_data", "Liquidity is not reported%s." % (" (Pump.fun bonding-curve pools often report none)" if p else ""), f, used, ["liquidity.usd"])
    used.append("liquidity.usd")
    st = S["settings"]
    f.append(Fd("Liquidity depth", "$%s" % format(int(liq), ","), "neg" if liq < st["min_liq"] else "pos" if liq >= 250000 else "neu", "DexScreener liquidity.usd (your minimum: $%s)" % format(int(st["min_liq"]), ",")))
    imp1k, imp10k = 2000.0 / liq * 100, 20000.0 / liq * 100
    f.append(Fd("Estimated exit impact (estimate)", "A $1,000 sale would move price about %.1f%%, a $10,000 sale about %.1f%% (constant-product approximation: 2 x size / liquidity; concentrated-liquidity pools differ)" % (min(imp1k, 100), min(imp10k, 100)),
                "neg" if imp1k >= 5 else "neu" if imp1k >= 1 else "pos", "derived from liquidity.usd"))
    if c["fdv"]:
        used.append("fdv")
        r = liq / c["fdv"] * 100
        f.append(Fd("Liquidity vs FDV", "%.2f%% of fully diluted valuation" % r, "neg" if r < 1 else "neu", "liquidity.usd / fdv"))
    pts = [x for x in h if x[0] >= time.time() - 3600 and x[2]]
    chg = None
    if len(pts) >= 3 and pts[-1][0] - pts[0][0] >= 600:
        chg = 100.0 * (pts[-1][2] / pts[0][2] - 1)
        used.append("locally collected liquidity snapshots")
        f.append(Fd("Liquidity change (locally collected)", "%+.1f%% over %.0f minutes" % (chg, (pts[-1][0] - pts[0][0]) / 60), "neg" if chg <= -20 else "pos" if chg >= 20 else "neu", "this app's snapshots"))
    else:
        missing.append("liquidity change (needs 10+ minutes of snapshots collected by this app)")
    sig = "bearish" if (liq < st["min_liq"] or imp1k >= 5 or (chg is not None and chg <= -20)) else "bullish" if (liq >= 250000 and imp1k < 1) else "neutral"
    return R(sig, "Exit-risk view: %s." % ("high" if sig == "bearish" else "low" if sig == "bullish" else "moderate"), f, used, missing, impact_1k=imp1k)


CONCL = ("BUY SETUP TO INVESTIGATE", "WAIT FOR CONFIRMATION", "AVOID / HIGH RISK", "INSUFFICIENT DATA — NO TRADE")
SIGLABEL = {"bullish": "supportive", "bearish": "concerning", "neutral": "neutral", "no_data": "no data", "error": "error"}
AGN = {"trend": "Trend", "volume": "Volume", "liquidity": "Liquidity", "bot": "Bot pattern", "whale": "Whale/wallet", "risk": "Risk"}


def consensus(c, ag, ai, tr):
    st = S["settings"]
    t, v, l, b, wh, r = (ag[k] for k in ("trend", "volume", "liquidity", "bot", "whale", "risk"))
    reasons, notes, inval = [], [], []
    stale = is_stale(c)
    miss = [AGN[k] for k in ("trend", "liquidity") if ag[k]["signal"] in ("no_data", "error")]
    sig = {k: ag[k]["signal"] for k in AGN}
    voters = [k for k in ("trend", "volume", "liquidity", "bot", "whale") if sig[k] in ("bullish", "bearish")]
    agree = [AGN[k] for k in voters if sig[k] == sig[voters[0]]] if voters else []
    pos_k = [AGN[k] for k in voters if sig[k] == "bullish"]
    neg_k = [AGN[k] for k in voters if sig[k] == "bearish"] + (["Risk"] if r["hard"] else [])
    conflicts = [(AGN[x], AGN[y]) for x in ("trend", "volume", "whale") for y in ("liquidity", "bot", "volume", "whale", "trend") if x < y and {sig[x], sig[y]} == {"bullish", "bearish"}]
    if stale:
        concl = CONCL[3]
        reasons.append("Price data is stale (last updated %ds ago), so it is not reliable for a setup." % (time.time() - c["updated"]))
    elif miss:
        concl = CONCL[3]
        reasons.append("%s data is unavailable, so no setup can be assessed." % " and ".join(miss))
    elif r["hard"]:
        concl = CONCL[2]
        reasons += ["Risk filter: " + x for x in r["hard"]]
    elif sig["bot"] == "bearish" and not tr:
        concl = CONCL[1]
        reasons.append("Snapshot indicators suggest manipulation; fetch transactions to confirm or reject before any conclusion.")
    elif sig["bot"] == "bearish":
        concl = CONCL[2]
        reasons.append("Several suspected automated or manipulative patterns fired (%s)." % "; ".join(x["factor"] for x in b["findings"] if x["dir"] == "neg")[:160])
    elif sig["trend"] == "bearish" and ("bearish" in (sig["volume"], sig["whale"]) or sig["liquidity"] == "bearish"):
        concl = CONCL[2]
        reasons.append("Price is falling and volume, wallet flow or liquidity confirms the weakness.")
    elif sig["trend"] == "bullish" and sig["liquidity"] != "bearish" and "bullish" in (sig["volume"], sig["whale"]) and "bearish" not in (sig["volume"], sig["whale"]):
        if not tr:
            concl = CONCL[1]
            reasons.append("Trend and volume look supportive, but bot-pattern and wallet checks have not run because no transactions were fetched. Fetch them before treating this as a setup.")
        elif conflicts:
            concl = CONCL[1]
            reasons.append("Agents contradict each other (%s)." % "; ".join("%s vs %s" % x for x in conflicts))
        else:
            concl = CONCL[0]
            reasons.append("Trend is up, liquidity is not flagged, %s support it, and bot/wallet checks found no bearish pattern." % " and ".join(n for n, k in (("volume", "volume"), ("wallet flow", "whale")) if sig[k] == "bullish"))
    else:
        concl = CONCL[1]
        reasons.append("Signals are mixed or unconfirmed: trend %s, volume %s, liquidity %s, bot patterns %s, wallet flow %s." % (SIGLABEL[sig["trend"]], SIGLABEL[sig["volume"]], SIGLABEL[sig["liquidity"]], SIGLABEL[sig["bot"]], SIGLABEL[sig["whale"]]))
    if ai:
        if concl == CONCL[0] and ai["conclusion"] != CONCL[0]:
            concl = CONCL[1]
            notes.append("Downgraded to WAIT FOR CONFIRMATION because the AI analyst (%s) disagrees: it concluded %s." % (ai["model"], ai["conclusion"]))
        else:
            notes.append("The AI analyst concluded %s (%s confidence)." % (ai["conclusion"], ai["confidence"]))
    if concl == CONCL[0]:
        if c["chg"].get("h1") is not None:
            inval.append("1h price change turns negative (currently %+.1f%%)" % c["chg"]["h1"])
        inval += ["Liquidity falls below your minimum of $%s" % format(int(st["min_liq"]), ","), "Volume falls back below 1.5x its 24h hourly average", "Large wallets turn net sellers, or bot/coordination patterns appear", "Data becomes stale or a provider fails"]
    elif concl == CONCL[1]:
        inval += ["Trend, volume and wallet flow align with transaction checks completed and no risk flag (would upgrade to a setup to investigate)", "A risk flag or confirmed selling appears (would downgrade to AVOID)"]
    elif concl == CONCL[2]:
        inval.append("The listed risk filters clear (liquidity, age, checklist tally, bot patterns) and trend turns up with confirmation")
    else:
        inval.append("Fresh data for the missing inputs becomes available")
    checks = [("Data is fresh", not stale), ("Trend data available", sig["trend"] not in ("no_data", "error")), ("Volume data available", sig["volume"] not in ("no_data", "error")),
              ("Liquidity data available", sig["liquidity"] not in ("no_data", "error")), ("Transaction-level data fetched", tr is not None),
              ("Agents do not contradict each other", not conflicts and not ({"bullish", "bearish"} <= {sig["trend"], sig["volume"], sig["whale"]})), ("Independent AI analysis available and consistent", bool(ai) and ai["conclusion"] == concl)]
    n_ok = sum(1 for _, ok in checks if ok)
    level = "low" if concl == CONCL[3] else "high" if n_ok >= 6 else "medium" if n_ok >= 4 else "low"
    return {"signal": {CONCL[0]: "bullish", CONCL[2]: "bearish"}.get(concl, "neutral"), "conclusion": concl, "summary": " ".join(reasons + notes),
            "findings": [Fd(n, "yes" if ok else "no", "pos" if ok else "neg", "confidence check") for n, ok in checks], "used": ["trend", "volume", "liquidity", "bot", "whale", "risk"] + (["ai"] if ai else []),
            "missing": [] if ai else ["fresh AI analysis (optional)"], "reasons": reasons, "notes": notes, "invalidation": inval, "agree": agree, "supportive": pos_k, "concerning": neg_k, "conflicts": [list(x) for x in conflicts],
            "confidence": {"level": level, "checks": n_ok, "of": len(checks), "explain": "%d of %d checks passed. Confidence reflects data completeness and agreement between agents. It does not forecast price moves, and no probability of any outcome is computed because no validated, back-tested model exists here." % (n_ok, len(checks))},
            "ai_used": bool(ai)}


def analyse(c):
    with LOCK:
        h = list(S["hist"].get(c["key"], []))
        tr = analyse_trades(c, trade_list(c["key"]))
        tc = cached_tech(c["key"])
        out = {"tech": tc and {"n": tc["n"], "fetched": tc["fetched"], "tf": tc["tf"]}}
        for name, fn in (("trend", agent_trend), ("volume", agent_volume), ("liquidity", agent_liquidity), ("risk", agent_risk), ("bot", agent_bot), ("whale", agent_whale)):
            t0 = time.perf_counter()
            try:
                r = fn(c, h, tr, tc)
            except Exception as e:
                r = R("error", "Agent crashed: %s" % e, [], [], [])
            r["ms"] = round((time.perf_counter() - t0) * 1000, 2)
            out[name] = r
            note_agent(name, r, r["ms"])
        t0 = time.perf_counter()
        try:
            cons = consensus(c, out, fresh_ai(c["key"]), tr)
        except Exception as e:
            cons = R("error", "Agent crashed: %s" % e, [], [], [], conclusion=CONCL[3], reasons=[], notes=[], invalidation=[], agree=[], supportive=[], concerning=[], conflicts=[],
                     confidence={"level": "low", "checks": 0, "of": 7, "explain": ""}, ai_used=False)
        cons["ms"] = round((time.perf_counter() - t0) * 1000, 2)
        note_agent("consensus", cons, cons["ms"])
        out["consensus"], out["ts"] = cons, time.time()
        return out


def wallet_profile(addr, chain, rpc=False):
    """Observed activity for one wallet from trades this app fetched, plus optional Solana RPC signatures."""
    if not ADDR_RE.match(addr):
        raise ApiError("That does not look like a wallet address", True)
    key = (lambda x: x) if chain == "solana" else (lambda x: x.lower())
    rows = []
    with LOCK:
        for k, t in S["trades"].items():
            co = S["coins"].get(k)
            for r in t["rows"].values():
                if key(r["wallet"]) == key(addr):
                    rows.append(dict(r, sym=co["sym"] if co else k.split(":")[1][:6], key=k, chain=k.split(":")[0], link=explorer(k.split(":")[0], "tx", r["tx"])))
    rows.sort(key=lambda r: -r["t"])
    bu, su = sum(r["usd"] for r in rows if r["kind"] == "buy"), sum(r["usd"] for r in rows if r["kind"] == "sell")
    out = {"address": addr, "chain": chain, "observed": rows[:100], "n": len(rows), "buy_usd": bu, "sell_usd": su, "coins": sorted({r["sym"] for r in rows}), "explorer": explorer(chain, "wallet", addr),
           "facts": "Wallet address, transaction hash and timestamp come directly from the provider and are verifiable on the explorer.",
           "estimates": "USD values are the provider's estimate at trade time. Buy/sell direction is relative to the token shown.",
           "limits": ["Only trades this app fetched (at most the last 300 per pool, 24h) are included: this is NOT the wallet's full history.", "No performance history is computed, so the wallet is not labelled 'smart money'."], "solana": None, "solana_error": None}
    if chain == "solana" and rpc:
        try:
            out["solana"] = solana_wallet_lookup(addr)
            for s in out["solana"]["recent"]:
                s["link"] = explorer("solana", "tx", s["sig"])
        except ApiError as e:
            out["solana_error"] = str(e)
    elif chain != "solana":
        out["limits"].append("Full history for this chain needs an explorer/indexer API key (e.g. Etherscan-family) which is not connected.")
    return out


def make_report(c):
    """Decision-support research report assembled from agent findings. A research conclusion, not a trade instruction."""
    with LOCK:
        a = c["analysis"]
        cons, ai = a["consensus"], fresh_ai(c["key"])
        names = ("trend", "volume", "liquidity", "bot", "whale", "risk")
        sec = lambda ag: [{"factor": f["factor"], "obs": f["obs"], "dir": f["dir"], "ev": f["ev"]} for f in a[ag]["findings"]]
        allf = [(n, f) for n in names for f in a[n]["findings"]]
        miss = sorted({m for n in names for m in a[n]["missing"]})
        cats = ["Listed project links (unverified): " + ", ".join(x[0] for x in c["links"])] if c.get("links") else []
        if c.get("boosts"):
            cats.append("DexScreener shows %d active boost(s): paid promotion draws attention but is not a fundamental catalyst" % c["boosts"])
        chg = c["chg"]
        happening = "Price %s over 1h and %s over 24h. " % (("%+.1f%%" % chg["h1"]) if chg.get("h1") is not None else "N/A", ("%+.1f%%" % chg["h24"]) if chg.get("h24") is not None else "N/A")
        happening += a["volume"]["findings"][0]["obs"] + ". " if a["volume"]["findings"] else ""
        happening += "Liquidity %s." % ("$" + format(int(c["liq"]), ",") if c.get("liq") else "N/A")
        lq = a["liquidity"]
        liq_ok = ("Liquidity data is unavailable." if lq["signal"] == "no_data" else
                  "Not adequate for further investigation by your own settings: " + lq["summary"] if lq["signal"] == "bearish" else "No liquidity red flag from the available data. " + lq["summary"])
        bt = a["bot"]
        sus = ("; ".join(f["factor"] + ": " + f["obs"] for f in bt["findings"] if f["dir"] == "neg") or "No suspected automated or coordinated pattern was flagged") + (". Transaction-level checks have not run." if bt.get("partial") else ".")
        sc = {"bullish": ["Price momentum persists across the 5m, 1h and 6h windows", "Volume stays above about 1.5x its 24h hourly average", "Buy-side flow stays ahead of sells and large wallets do not sell into strength", "Liquidity holds or grows"],
              "neutral": ["Price consolidates with the 1h change inside about +/-1%", "Volume falls back toward its 24h average", "Buy and sell counts stay roughly balanced"],
              "bearish": ["Price loses its 1h and 6h gains", "Sell-side flow exceeds buys or large wallets start net selling", "Liquidity falls, widening exit slippage", "A risk filter (liquidity, age, concentration, bot patterns) triggers"]}
        lean = "bullish" if a["trend"]["signal"] == "bullish" and not cons["concerning"] else "bearish" if a["trend"]["signal"] == "bearish" or len(cons["concerning"]) >= 2 else "neutral"
        gt = S["trades"].get(c["key"], {}).get("fetched")
        return {"key": c["key"], "sym": c["sym"], "generated": time.time(), "data_ts": c["updated"], "stale": is_stale(c), "conclusion": cons["conclusion"], "conclusion_reason": cons["summary"],
                "whats_happening": happening, "agree": cons["agree"], "supportive": cons["supportive"], "concerning": cons["concerning"], "conflicts": cons["conflicts"],
                "evidence": {n: [f["factor"] + ": " + f["obs"] for f in a[n]["findings"]][:6] for n in names}, "liquidity_adequacy": liq_ok, "suspicious_activity": sus,
                "invalidation": cons["invalidation"], "missing": miss, "trend": sec("trend"), "momentum_volume": sec("volume"), "liquidity_exit": sec("liquidity"), "bot_patterns": sec("bot"),
                "wallet_activity": sec("whale"), "risk_checklist": sec("risk"), "positives": ["%s: %s" % (f["factor"], f["obs"]) for n, f in allf if f["dir"] == "pos"], "negatives": ["%s: %s" % (f["factor"], f["obs"]) for n, f in allf if f["dir"] == "neg"],
                "catalysts": cats or ["No catalyst is supported by the supplied data."], "lean": lean, "scenarios": sc, "confidence": cons["confidence"], "ai": ai, "pump": pump_info(c),
                "sources": [{"name": "DexScreener public API", "what": "price, volume, liquidity, FDV/market cap, transaction counts, pair age", "ts": c["updated"], "kind": "live"},
                            {"name": "GeckoTerminal public API (pool trades)", "what": "individual trades, wallets, USD estimates", "ts": gt, "kind": "cached" if gt else "unavailable"},
                            {"name": "GeckoTerminal public API (OHLCV candles)", "what": "candles; indicators are calculated by this app", "ts": (a.get("tech") or {}).get("fetched"), "kind": "cached" if a.get("tech") else "unavailable"},
                            {"name": "Locally collected snapshots", "what": "price/liquidity points collected by this app since startup", "ts": None, "kind": "local"}],
                "disclaimer": "Research conclusion only: no orders are placed and nothing here predicts the future or guarantees any outcome. A favourable conclusion does not mean a coin is safe."}


# ----------------------------------------------------------------------------- AI layer: prompts and validators (override of earlier definitions)
AI_COMMON = ("You are a cautious crypto market-research analyst inside a research-only monitoring tool (no trading, no orders). Use ONLY the JSON data in the user message. "
             "A null value means unavailable. Do not invent numbers, wallets, news, social sentiment, or on-chain facts. The 'deterministic_indicators' are software-computed hints, not truth. "
             "Never promise profit, never give a probability of profit, never present predictions as facts, never call an address a confirmed bot (use 'suspected' and cite the evidence). "
             "If data is stale, missing or contradictory, abstain with INSUFFICIENT DATA — NO TRADE or WAIT FOR CONFIRMATION. Respond with ONE JSON object and nothing else. ")
CONC_TXT = '"conclusion" (exactly one of: BUY SETUP TO INVESTIGATE, WAIT FOR CONFIRMATION, AVOID / HIGH RISK, INSUFFICIENT DATA — NO TRADE)'
AI_SYSTEM_COIN = AI_COMMON + (
    'Keys: "what_is_happening" (string), "agreements_and_disagreements" (string naming which software agents agree or conflict), "market_trend" (string), "momentum_volume_interpretation" (string), '
    '"liquidity_exit_assessment" (string, say whether liquidity is adequate for further investigation), "wallet_activity_assessment" (string), "suspicious_activity_assessment" (string; bot-like or coordinated patterns, labelled suspected), '
    '"positive_factors" (list), "negative_factors" (list), "potential_catalysts" (list, only items supported by the data, else empty), "key_risks" (list, include risks the data cannot check), '
    '"missing_information" (list), "manipulation_indicators" (list, may be empty), "scenario" (bullish, neutral or bearish), "scenario_reasoning" (string), ' + CONC_TXT + ', '
    '"confidence" (low, medium or high), "confidence_explanation" (string with limitations), "reasons" (non-empty list), "invalidation_conditions" (non-empty list).')
AI_SYSTEM_MARKET = AI_COMMON + (
    'This is a MARKET-level request about a SAMPLE of monitored tokens, not the whole market. Keys: "regime" (bullish, bearish, sideways or unclear), "regime_reason" (string), '
    '"bullish_evidence" (list), "bearish_evidence" (list), "risks" (list), "missing_information" (list), "uncertainty" (string), ' + CONC_TXT + ' (overall stance toward researching new longs), '
    '"confidence" (low, medium or high), "reasons" (non-empty list), "invalidation_conditions" (non-empty list).')


def validate_coin_ai(o):
    return {"conclusion": _enum(o, "conclusion", CONCL), "confidence": _enum(o, "confidence", ("low", "medium", "high")), "scenario": _enum(o, "scenario", ("bullish", "neutral", "bearish")),
            "what_is_happening": _s(o, "what_is_happening", req=True), "agreements": _s(o, "agreements_and_disagreements"), "market_trend": _s(o, "market_trend"), "momentum_volume": _s(o, "momentum_volume_interpretation"),
            "liquidity_exit": _s(o, "liquidity_exit_assessment"), "wallet_activity": _s(o, "wallet_activity_assessment"), "suspicious": _s(o, "suspicious_activity_assessment"),
            "positives": _l(o, "positive_factors"), "negatives": _l(o, "negative_factors"), "catalysts": _l(o, "potential_catalysts"), "risks": _l(o, "key_risks"), "missing": _l(o, "missing_information"),
            "manipulation": _l(o, "manipulation_indicators"), "scenario_reasoning": _s(o, "scenario_reasoning"), "confidence_explanation": _s(o, "confidence_explanation", req=True),
            "reasons": _l(o, "reasons", True), "invalidation": _l(o, "invalidation_conditions", True)}


def coin_payload(c):
    h = list(S["hist"].get(c["key"], []))
    sess = None
    if len(h) >= 2:
        pr = [p[1] for p in h]
        sess = {"snapshots": len(h), "hours_covered": round((h[-1][0] - h[0][0]) / 3600, 2), "first": pr[0], "last": pr[-1], "min": min(pr), "max": max(pr), "note": "collected by this app since startup"}
    a, oc = c["analysis"], S["onchain"].get(c["key"])
    tc = cached_tech(c["key"])
    return {"task": "coin_analysis", "data_sources": ["DexScreener public API", "GeckoTerminal pool trades and OHLCV (if present)", "app-recorded snapshots"], "data_timestamp_utc": iso(c["updated"]),
            "data_stale": is_stale(c), "coin": {"symbol": c["sym"], "name": c["name"], "chain": c["chain"], "token_address": c["addr"], "dex": c["dex"], "price_usd": c["price"], "price_change_pct": c["chg"], "volume_usd": c["vol"],
                                              "transactions": c["tx"], "liquidity_usd": c["liq"], "fdv_usd": c["fdv"], "market_cap_usd": c["mcap"], "pair_age_hours": age_h(c), "pump_fun": pump_info(c)},
            "deterministic_indicators": {k: {"signal": a[k]["signal"], "summary": a[k]["summary"], "findings": [{"factor": f["factor"], "observation": f["obs"]} for f in a[k]["findings"][:8]], "unavailable": a[k]["missing"]}
                                         for k in ("trend", "volume", "liquidity", "risk", "bot", "whale")},
            "software_conclusion": a["consensus"]["conclusion"], "software_agreement": {"supportive": a["consensus"]["supportive"], "concerning": a["consensus"]["concerning"], "conflicts": a["consensus"]["conflicts"]},
            "calculated_candle_signals": [s["text"] for s in tc["signals"]] if tc else None, "transactions_analysis": tr_payload(analyse_trades(c, trade_list(c["key"]))), "session_snapshots": sess,
            "holder_concentration": ({k: oc[k] for k in ("top1_pct", "top5_pct", "top10_pct", "caveat")} if oc else None),
            "notes": ["null means unavailable", "transaction counts are not unique wallets", "this data cannot reveal wallet identities", "contract-level checks (honeypot, mint authority, LP lock) were not performed"]}


PAGE = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Meme Desk Live v3: market intelligence terminal</title>
<style>
:root{--bg:#04060c;--pn:#0a0f1d;--pn2:#101830;--ln:#1f2a48;--tx:#e6ecff;--mu:#8a96bd;--cy:#38e1ff;--vi:#8b6bff;--up:#2dffa6;--dn:#ff4d6d;--wn:#ffc43d;color-scheme:dark}
*{box-sizing:border-box}html,body{margin:0;max-width:100%;overflow-x:hidden}
body{background:radial-gradient(1200px 500px at 50% -10%,#0d1b3d 0,transparent 60%),var(--bg);color:var(--tx);font:14px/1.45 "Trebuchet MS",system-ui,sans-serif;padding-bottom:calc(60px + env(safe-area-inset-bottom,0px));-webkit-text-size-adjust:100%}
header{position:sticky;top:0;z-index:6;background:rgba(4,6,12,.92);border-bottom:1px solid var(--ln);padding:calc(8px + env(safe-area-inset-top,0px)) 12px 8px;display:flex;gap:8px;align-items:center;justify-content:space-between;flex-wrap:wrap}
.brand{font-weight:700;letter-spacing:.06em;color:var(--cy)}.brand small{display:block;color:var(--wn);font-weight:400;font-size:10px;letter-spacing:.02em}
button{background:linear-gradient(180deg,#5a46d6,#4333ac);color:#fff;border:1px solid #6d5af0;border-radius:8px;padding:8px 12px;font:inherit;min-height:38px;cursor:pointer}
button.sec{background:var(--pn2);border:1px solid var(--ln);color:var(--tx)}button.bad{background:#a82a44;border-color:var(--dn)}button.sm{min-height:30px;padding:3px 9px;font-size:12px}
button:disabled{opacity:.45;cursor:not-allowed}:focus-visible{outline:2px solid var(--wn);outline-offset:2px}
main{padding:10px;max-width:1000px;margin:auto}
.card{position:relative;background:linear-gradient(180deg,rgba(16,24,48,.85),rgba(10,15,29,.92));border:1px solid var(--ln);border-radius:10px;padding:12px;margin-bottom:10px;min-width:0}
.card:before,.card:after{content:"";position:absolute;width:10px;height:10px;border:1px solid var(--cy);opacity:.55}.card:before{top:-1px;left:-1px;border-right:0;border-bottom:0;border-top-left-radius:10px}.card:after{bottom:-1px;right:-1px;border-left:0;border-top:0;border-bottom-right-radius:10px}
h2{font-size:13px;margin:0 0 8px;color:var(--cy);letter-spacing:.08em;text-transform:uppercase}h3{font-size:12px;margin:10px 0 4px;color:var(--mu);letter-spacing:.04em}
.mu{color:var(--mu)}.up{color:var(--up)}.dn{color:var(--dn)}.wn{color:var(--wn)}.s{font-size:12px}.num{font-family:"Courier New",monospace}
.pill{display:inline-block;border-radius:99px;padding:1px 9px;font-size:11px;border:1px solid var(--ln);white-space:nowrap;vertical-align:middle}
.b-bullish,.b-up,.b-online,.b-idle,.b-ok{background:rgba(45,255,166,.12);color:var(--up);border-color:var(--up)}
.b-bearish,.b-dn,.b-offline,.b-error{background:rgba(255,77,109,.12);color:var(--dn);border-color:var(--dn)}
.b-neutral,.b-wn,.b-degraded,.b-running,.b-rate_limited,.b-sideways{background:rgba(255,196,61,.12);color:var(--wn);border-color:var(--wn)}
.b-no_data,.b-not_configured,.b-unavailable,.b-starting,.b-insufficient,.b-gr{background:var(--pn2);color:var(--mu)}
.pv{display:inline-block;font-size:10px;letter-spacing:.05em;border-radius:4px;padding:0 5px;margin-right:4px;border:1px solid var(--ln);color:var(--mu)}
.pv.live{color:var(--up);border-color:var(--up)}.pv.local{color:var(--vi);border-color:var(--vi)}.pv.cached{color:var(--cy);border-color:var(--cy)}.pv.est{color:var(--wn);border-color:var(--wn)}.pv.na{color:var(--dn);border-color:var(--dn)}
.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:8px}.g4{grid-template-columns:repeat(4,1fr)}.g3{grid-template-columns:repeat(3,1fr)}
.kv b{display:block;font:600 15px "Courier New",monospace;overflow-wrap:anywhere}.kv span{color:var(--mu);font-size:11px}
.row{display:flex;gap:8px;align-items:end;flex-wrap:wrap}.row>*{flex:1;min-width:110px}.row>.fit{flex:0 0 auto;min-width:0}
input,select{background:var(--bg);color:var(--tx);border:1px solid var(--ln);border-radius:8px;padding:8px;font:inherit;min-height:38px;width:100%}
input[type=checkbox]{width:auto;min-height:0}label{display:block;font-size:11px;color:var(--mu);margin-top:6px}label.ck{display:flex;gap:6px;align-items:center}
.tw{overflow-x:auto;max-width:100%}table{border-collapse:collapse;width:100%;font-size:12px}th,td{padding:6px;text-align:right;border-top:1px solid var(--ln);white-space:nowrap}th:first-child,td:first-child{text-align:left}th{color:var(--mu);font-weight:400;cursor:default}th.sr{cursor:pointer;color:var(--cy)}
tr.r{cursor:pointer}tr.r:hover{background:rgba(56,225,255,.06)}td.wrap{white-space:normal;text-align:left;min-width:200px}
nav{position:fixed;bottom:0;left:0;right:0;background:rgba(10,15,29,.97);border-top:1px solid var(--ln);display:flex;overflow-x:auto;padding-bottom:env(safe-area-inset-bottom,0px);z-index:7}
nav button{flex:1 0 auto;background:none;border:0;color:var(--mu);border-radius:0;min-height:50px;padding:4px 11px;font-size:12px}nav button.on{color:var(--cy);box-shadow:inset 0 2px 0 var(--cy)}
@media(min-width:900px){nav{position:sticky;top:58px;bottom:auto;border-top:0;border-bottom:1px solid var(--ln)}body{padding-bottom:20px}}
.star{background:none;border:0;color:var(--mu);font-size:19px;padding:0 6px;min-height:30px}.star.on{color:var(--wn)}
canvas{width:100%;display:block;background:rgba(0,0,0,.25);border-radius:6px}ul{margin:4px 0;padding-left:18px}li{margin:3px 0}
.concl{border-width:2px;text-align:center;padding:16px 10px}.concl .big{font:700 18px "Trebuchet MS",sans-serif;letter-spacing:.04em}
.c-buy{border-color:var(--up);box-shadow:0 0 18px rgba(45,255,166,.18)}.c-buy .big{color:var(--up)}.c-wait{border-color:var(--wn)}.c-wait .big{color:var(--wn)}.c-avoid{border-color:var(--dn);box-shadow:0 0 18px rgba(255,77,109,.18)}.c-avoid .big{color:var(--dn)}.c-ins{border-color:var(--mu)}.c-ins .big{color:var(--mu)}
.banner{background:rgba(255,196,61,.1);border:1px solid var(--wn);color:var(--wn);border-radius:8px;padding:8px 10px;margin-bottom:10px;font-size:12px}
.spin{display:inline-block;width:12px;height:12px;border:2px solid var(--ln);border-top-color:var(--cy);border-radius:50%;animation:sp 1s linear infinite;vertical-align:-2px}@keyframes sp{to{transform:rotate(360deg)}}
.f{display:flex;gap:6px;align-items:flex-start;padding:5px 0;border-top:1px dashed var(--ln)}.f:first-child{border-top:0}.fi{flex:0 0 14px;font-weight:700}.fe{color:var(--mu);font-size:11px}
.cl{cursor:pointer}.coin{display:flex;gap:8px;align-items:center}.coin img{width:26px;height:26px;border-radius:50%;background:var(--pn2)}
#toast{position:fixed;left:10px;right:10px;bottom:calc(66px + env(safe-area-inset-bottom,0px));z-index:30;pointer-events:none}#toast div{background:var(--pn2);border:1px solid var(--ln);border-radius:8px;padding:9px;margin-top:6px}#toast .e{border-color:var(--dn)}
svg.core{width:100%;max-width:520px;margin:auto;display:block}svg .nd{cursor:pointer}svg .run{animation:sp 1.6s linear infinite;transform-box:fill-box;transform-origin:center}svg .flow{animation:dash 1s linear infinite}@keyframes dash{to{stroke-dashoffset:-12}}
@media (prefers-reduced-motion:reduce){.spin,svg .run,svg .flow{animation:none}}
@media(max-width:520px){.g4{grid-template-columns:repeat(2,1fr)}.g3{grid-template-columns:repeat(2,1fr)}}
.coin-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(235px,1fr));gap:12px}.coin-tile{border:1px solid var(--bd);border-radius:12px;padding:14px;background:var(--pn);cursor:pointer;min-width:0}.coin-tile:hover{border-color:var(--mu)}.coin-head{display:flex;align-items:center;gap:10px}.coin-photo{width:46px;height:46px;object-fit:cover;border-radius:50%;background:#171717;flex-shrink:0}.coin-placeholder{display:grid;place-items:center;font-size:24px}.coin-meta{min-width:0;overflow-wrap:anywhere}.coin-price{font-size:22px;font-weight:700;margin:14px 0 8px}.coin-changes{display:flex;flex-wrap:wrap;gap:8px;font-size:12px}.coin-stats{display:grid;grid-template-columns:1fr 1fr;gap:7px;margin:12px 0;font-size:12px}.coin-stats span{display:flex;flex-direction:column;color:var(--mu)}.coin-stats b{color:var(--tx);margin-top:3px}.coin-verdict{margin:10px 0}.up{color:var(--up);font-weight:700}.dn{color:var(--dn);font-weight:700}@media(max-width:480px){.coin-grid{grid-template-columns:1fr 1fr;gap:8px}.coin-tile{padding:10px}.coin-photo{width:36px;height:36px}.coin-price{font-size:18px}.coin-stats{grid-template-columns:1fr}}</style></head><body>
<header><div class="brand">MEME DESK LIVE<small>RESEARCH ONLY · NO TRADING OR SIMULATION · NOT FINANCIAL ADVICE</small></div>
<div style="display:flex;gap:6px;align-items:center"><span id="conn" class="pill b-starting">starting</span><button id="rf" class="sec sm" type="button">Refresh</button></div></header>
<nav id="nav" aria-label="Sections"></nav>
<main><div id="banner"></div><div id="view"></div></main>
<div id="toast" aria-live="polite"></div>
<script>
"use strict";
const TOKEN="__TOKEN__";
const $=s=>document.querySelector(s);
const esc=s=>String(s==null?"":s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const fp=p=>p==null?"N/A":p>=1?p.toLocaleString(undefined,{maximumFractionDigits:4}):p>=0.0001?p.toFixed(6):p.toExponential(3);
const fu=n=>n==null?"N/A":"$"+(n>=1e9?(n/1e9).toFixed(2)+"B":n>=1e6?(n/1e6).toFixed(2)+"M":n>=1e3?(n/1e3).toFixed(1)+"K":n.toFixed(n<10?2:0));
const fc=v=>v==null?'<span class="mu">N/A</span>':'<span class="'+(v>=0?"up":"dn")+'">'+(v>=0?"+":"")+v.toFixed(1)+"%</span>";
const fa=h=>h==null?"N/A":h<48?h.toFixed(1)+"h":(h/24).toFixed(1)+"d";
const ago=t=>{if(!t)return"never";const s=Math.max(0,Date.now()/1000-t);return s<90?Math.round(s)+"s ago":s<5400?Math.round(s/60)+"m ago":Math.round(s/3600)+"h ago"};
const when=t=>t?new Date(t*1000).toLocaleString():"N/A";
const clk=t=>t?new Date(t*1000).toLocaleTimeString():"N/A";
const sh=a=>a&&a.length>12?a.slice(0,5)+"…"+a.slice(-4):(a||"");
const pill=(k,t)=>'<span class="pill b-'+esc(k)+'">'+esc(t==null?k:t)+"</span>";
const pv=(k,t)=>'<span class="pv '+k+'">'+k.toUpperCase()+"</span>"+(t?'<span class="s mu">'+esc(t)+"</span> ":"");
const SIG={bullish:"supportive",bearish:"concerning",neutral:"neutral",no_data:"no data",error:"error"};
const sg=s=>pill(s,SIG[s]||s);
const CL={"BUY SETUP TO INVESTIGATE":["c-buy","bullish","Buy setup to investigate"],"WAIT FOR CONFIRMATION":["c-wait","neutral","Wait for confirmation"],"AVOID / HIGH RISK":["c-avoid","bearish","Avoid / high risk"],"INSUFFICIENT DATA — NO TRADE":["c-ins","no_data","Insufficient data: no trade"]};
const cb=c=>c?pill((CL[c]||["","no_data"])[1],(CL[c]||[0,0,c])[2]):"";
function toast(m,bad){const d=document.createElement("div");d.textContent=m;if(bad)d.className="e";$("#toast").appendChild(d);setTimeout(()=>d.remove(),bad?6500:3000)}
async function api(path,opts){let r;try{r=await fetch(path,opts)}catch(e){throw new Error("Cannot reach the local server. Is the script still running?")}
 let j;try{j=await r.json()}catch(e){j={error:"Unreadable server response"}}if(!r.ok)throw new Error(j.error||"HTTP "+r.status);return j}
const post=(p,b)=>api(p,{method:"POST",headers:{"Content-Type":"application/json","X-Desk-Token":TOKEN},body:JSON.stringify(b||{})});
async function act(fn,ok){try{const r=await fn();if(ok||r.msg)toast(ok||r.msg);await poll(true);return r}catch(e){toast(e.message,true)}}

let ST=null,ver=-1,view="market",cur=null,D=null,TV=null,CD=null,RP=null,FEED=null,WP=null,agSel="consensus",tf="15m",gw="h1",drawn="",feedMode=false,sideF="all",minF=0,busy=false,errMsg="",sess=0,lastLoad=0,pumpF="";
const Fl={chain:"",minliq:0,maxrisk:101,watch:false,sortc:"vol",dir:-1};
const IND={ema:true,sma:true,vol:true,rsi:true,macd:true,sr:true};
const NAVS=[["market","Market"],["pump","Pump.fun"],["coins","Explorer"],["details","Details"],["candles","Candles"],["txns","Txns"],["bots","Bots"],["wallets","Wallets"],["core","AI Core"],["signal","Signal"],["watch","Watchlist"],["settings","Settings"]];
const SCOPED=["details","candles","txns","bots","core","signal"];
$("#nav").innerHTML=NAVS.map(n=>'<button type="button" data-v="'+n[0]+'">'+n[1]+"</button>").join("");

/* ---------- charts ---------- */
const css=n=>getComputedStyle(document.documentElement).getPropertyValue(n).trim()||"#888";
function cv0(cv){const dpr=window.devicePixelRatio||1,w=cv.clientWidth||300,h=cv.clientHeight||150;cv.width=Math.round(w*dpr);cv.height=Math.round(h*dpr);const x=cv.getContext("2d");x.setTransform(dpr,0,0,dpr,0,0);x.clearRect(0,0,w,h);x.font="10px sans-serif";return{x,w,h}}
function lineSeries(x,arr,X,Y,col,wd){x.strokeStyle=col;x.lineWidth=wd||1.5;x.beginPath();let st=false;arr.forEach((v,i)=>{if(v==null){st=false;return}st?x.lineTo(X(i),Y(v)):x.moveTo(X(i),Y(v));st=true});x.stroke()}
function drawLocal(cv,pts){const{x,w,h}=cv0(cv);if(!pts||pts.length<2){x.fillStyle=css("--mu");x.fillText("Not enough locally collected points yet",8,20);return}
 let mn=Infinity,mx=-Infinity;pts.forEach(p=>{mn=Math.min(mn,p[1]);mx=Math.max(mx,p[1])});const L=4,R=58,T=8,B=14,X=i=>L+i/(pts.length-1)*(w-L-R),Y=v=>T+(1-(v-mn)/(mx-mn||1))*(h-T-B);
 lineSeries(x,pts.map(p=>p[1]),X,Y,css("--cy"),2);x.fillStyle=css("--mu");x.fillText(fp(mx),w-R+3,T+8);x.fillText(fp(mn),w-R+3,h-B);x.fillText(clk(pts[0][0]),L,h-2);x.textAlign="right";x.fillText(clk(pts[pts.length-1][0]),w-R,h-2)}
function drawCandles(cv,d){const{x,w,h}=cv0(cv),rows=d.candles,n=rows.length,T=d.tech,L=4,R=58,Tp=6,Bt=14,ph=h-Tp-Bt,vh=IND.vol?ph*0.2:0,pH=ph-vh-4;
 let lo=Infinity,hi=-Infinity;rows.forEach(r=>{lo=Math.min(lo,r[3]);hi=Math.max(hi,r[2])});const cw=(w-L-R)/n,X=i=>L+(i+.5)*cw,Y=p=>Tp+(1-(p-lo)/(hi-lo||1))*pH;
 x.strokeStyle=css("--ln");x.fillStyle=css("--mu");x.lineWidth=1;for(let i=0;i<=3;i++){const p=lo+(hi-lo)*i/3,y=Y(p);x.beginPath();x.moveTo(L,y);x.lineTo(w-R,y);x.stroke();x.fillText(fp(p),w-R+3,y+3)}
 const up=css("--up"),dn=css("--dn"),mv=Math.max(...rows.map(r=>r[5]))||1;
 rows.forEach((r,i)=>{const c=r[4]>=r[1]?up:dn;x.strokeStyle=c;x.fillStyle=c;x.beginPath();x.moveTo(X(i),Y(r[2]));x.lineTo(X(i),Y(r[3]));x.stroke();const y1=Y(Math.max(r[1],r[4])),y2=Y(Math.min(r[1],r[4]));x.fillRect(X(i)-Math.max(cw*.35,.5),y1,Math.max(cw*.7,1),Math.max(y2-y1,1));
  if(IND.vol){x.globalAlpha=.45;x.fillRect(X(i)-Math.max(cw*.35,.5),Tp+pH+4+vh*(1-r[5]/mv),Math.max(cw*.7,1),vh*r[5]/mv);x.globalAlpha=1}});
 if(T){if(IND.ema)lineSeries(x,T.ema20,X,Y,css("--cy"),1.5);if(IND.sma)lineSeries(x,T.sma50,X,Y,css("--wn"),1.5);
  if(IND.sr){x.setLineDash([5,4]);[["support",up],["resistance",dn]].forEach(([k,c])=>T[k].forEach(s=>{if(s.level<lo||s.level>hi)return;x.strokeStyle=c;x.beginPath();x.moveTo(L,Y(s.level));x.lineTo(w-R,Y(s.level));x.stroke()}));x.setLineDash([])}}
 x.fillStyle=css("--mu");x.textAlign="left";x.fillText(clk(rows[0][0]),L,h-2);x.textAlign="right";x.fillText(clk(rows[n-1][0]),w-R,h-2);x.textAlign="left";
 cv._lay={L,cw,n};const tip=$("#tip");cv.onpointermove=cv.onclick=e=>{const b=cv.getBoundingClientRect(),i=Math.min(n-1,Math.max(0,Math.floor((e.clientX-b.left-L)/cw))),r=rows[i];if(tip)tip.textContent=new Date(r[0]*1000).toLocaleString()+"  O "+fp(r[1])+"  H "+fp(r[2])+"  L "+fp(r[3])+"  C "+fp(r[4])+"  Vol "+fu(r[5])}}
function drawRSI(cv,d){const{x,w,h}=cv0(cv),a=d.tech.rsi14,n=a.length,L=4,R=58,X=i=>L+(i+.5)*(w-L-R)/n,Y=v=>6+(1-v/100)*(h-12);
 x.strokeStyle=css("--ln");[30,70].forEach(v=>{x.setLineDash([4,4]);x.beginPath();x.moveTo(L,Y(v));x.lineTo(w-R,Y(v));x.stroke();x.fillStyle=css("--mu");x.fillText(v,w-R+3,Y(v)+3)});x.setLineDash([]);lineSeries(x,a,X,Y,css("--vi"),1.5);x.fillStyle=css("--mu");x.fillText("RSI(14)",L+2,10)}
function drawMACD(cv,d){const{x,w,h}=cv0(cv),T=d.tech,n=T.macd.length,L=4,R=58,all=[...T.macd,...T.macd_signal,...T.macd_hist].filter(v=>v!=null);if(!all.length)return;const mx=Math.max(...all.map(Math.abs))||1,X=i=>L+(i+.5)*(w-L-R)/n,Y=v=>h/2-v/mx*(h/2-8),cw=(w-L-R)/n;
 T.macd_hist.forEach((v,i)=>{if(v==null)return;x.fillStyle=v>=0?css("--up"):css("--dn");x.globalAlpha=.55;x.fillRect(X(i)-Math.max(cw*.35,.5),Math.min(Y(v),Y(0)),Math.max(cw*.7,1),Math.abs(Y(v)-Y(0)));x.globalAlpha=1});
 x.strokeStyle=css("--ln");x.beginPath();x.moveTo(L,Y(0));x.lineTo(w-R,Y(0));x.stroke();lineSeries(x,T.macd,X,Y,css("--cy"),1.3);lineSeries(x,T.macd_signal,X,Y,css("--wn"),1.3);x.fillStyle=css("--mu");x.fillText("MACD(12,26,9)",L+2,10)}

/* ---------- shared pieces ---------- */
function findings(a){return a.findings.length?a.findings.map(f=>'<div class="f"><span class="fi '+(f.dir==="pos"?"up":f.dir==="neg"?"dn":"mu")+'">'+(f.dir==="pos"?"+":f.dir==="neg"?"−":"·")+'</span><div><b>'+esc(f.factor)+":</b> "+esc(f.obs)+'<div class="fe">Evidence: '+esc(f.ev)+"</div></div></div>").join(""):'<div class="mu s">No findings (no data).</div>'}
function list(a,cls){return a&&a.length?"<ul"+(cls?' class="'+cls+'"':"")+">"+a.map(x=>"<li>"+esc(x)+"</li>").join("")+"</ul>":'<div class="mu s">None.</div>'}
function aiCard(r){if(!r)return"";const S=(t,v)=>v?"<h3>"+t+"</h3><p>"+esc(v)+"</p>":"",L=(t,a)=>a&&a.length?"<h3>"+t+"</h3>"+list(a):"";
 const hd='<div class="s mu">REAL LLM ANALYSIS (not a fact, not a guarantee) · model '+esc(r.provider)+" / "+esc(r.model)+" · analysed "+when(r.analyzed_at)+" · market data from "+when(r.data_ts)+" · "+r.ms+" ms · confidence "+esc(r.confidence)+"</div>";
 if(r.kind==="market")return '<div class="card"><h2>AI market analysis '+cb(r.conclusion)+" "+pill(r.regime)+"</h2>"+hd+S("Regime",r.regime_reason)+L("Bullish evidence",r.bullish)+L("Bearish evidence",r.bearish)+L("Risks",r.risks)+L("Missing information",r.missing)+S("Uncertainty",r.uncertainty)+L("Reasons",r.reasons)+L("Would invalidate it",r.invalidation)+"</div>";
 return '<div class="card"><h2>AI analysis: '+esc(r.sym)+" "+cb(r.conclusion)+" "+pill(r.scenario==="bullish"?"bullish":r.scenario==="bearish"?"bearish":"neutral","leans "+r.scenario)+"</h2>"+hd+S("What is happening",r.what_is_happening)+S("Agents: agreement and conflicts",r.agreements)+S("Trend",r.market_trend)+S("Momentum and volume",r.momentum_volume)+S("Liquidity and exit",r.liquidity_exit)+S("Wallet activity",r.wallet_activity)+S("Suspicious activity (suspected, not proof)",r.suspicious)+
  L("Positive factors",r.positives)+L("Negative factors",r.negatives)+L("Potential catalysts (data-supported only)",r.catalysts)+L("Key risks",r.risks)+L("Missing information",r.missing)+L("Abnormal-activity indicators",r.manipulation)+S("Scenario reasoning",r.scenario_reasoning)+S("Confidence and limits",r.confidence_explanation)+L("Reasons",r.reasons)+L("Would invalidate it",r.invalidation)+"</div>"}
function coinTable(a,empty){const arrow=c=>Fl.sortc===c?(Fl.dir<0?" ▼":" ▲"):"",th=(c,l)=>'<th class="sr" data-sort="'+c+'">'+l+arrow(c)+"</th>";
 if(!a.length)return '<div class="mu">'+empty+"</div>";
 return '<div class="tw"><table><thead><tr><th class="sr" data-sort="sym">Coin'+arrow("sym")+"</th>"+th("price","Price")+th("m5","5m")+th("h1","1h")+th("h24","24h")+th("liq","Liquidity")+th("vol","Vol 24h")+th("age","Age")+th("risk","Risk tally")+"<th>Verdict</th><th></th></tr></thead><tbody>"+
 a.map(c=>'<tr class="r" tabindex="0" data-k="'+esc(c.key)+'"><td><span class="coin">'+(c.logo?'<img src="'+esc(c.logo)+'" alt="" loading="lazy">':"")+"<span><b>"+esc(c.sym)+'</b> <span class="mu s">'+esc(c.chain)+"</span>"+(c.pump?' <span class="pill b-neutral">Pump.fun?</span>':"")+(c.stale?' <span class="pill b-bearish">stale</span>':"")+"</span></span></td><td class=\"num\">"+fp(c.price)+"</td><td>"+fc(c.chg.m5)+"</td><td>"+fc(c.chg.h1)+"</td><td>"+fc(c.chg.h24)+"</td><td>"+fu(c.liq)+"</td><td>"+fu(c.vol24)+"</td><td>"+fa(c.age_h)+"</td><td>"+(c.risk==null?"N/A":c.risk)+"</td><td>"+cb(c.concl)+'</td><td><button type="button" class="star'+(c.watch?" on":"")+'" data-act="watch" data-k="'+esc(c.key)+'" aria-label="Toggle watchlist">'+(c.watch?"★":"☆")+"</button></td></tr>").join("")+"</tbody></table></div>"}
function sortedCoins(a){const v={sym:c=>c.sym.toLowerCase(),price:c=>c.price,m5:c=>c.chg.m5,h1:c=>c.chg.h1,h24:c=>c.chg.h24,liq:c=>c.liq,vol:c=>c.vol24,age:c=>c.age_h,risk:c=>c.risk}[Fl.sortc];
 return a.slice().sort((x,y)=>{const p=v(x),q=v(y);if(p==null&&q==null)return 0;if(p==null)return 1;if(q==null)return -1;return(p<q?-1:p>q?1:0)*Fl.dir})}
const mrow=(c,w)=>'<div class="lrow cl" tabindex="0" role="button" data-k="'+esc(c.key)+'" style="display:flex;gap:8px;padding:7px 2px;border-top:1px solid var(--ln)"><b>'+esc(c.sym)+'</b><span class="tag mu s">'+esc(c.chain)+'</span><span style="flex:1"></span><span class="num">'+fp(c.price)+"</span><span>"+fc(c[w])+"</span></div>";
const mlist=(t,a,w,e)=>'<div class="card"><h2>'+t+"</h2>"+(a&&a.length?a.map(c=>mrow(c,w)).join(""):'<div class="mu s">'+(e||"Nothing to show yet.")+"</div>")+"</div>";
const alertRow=a=>'<div class="f"><span class="fi '+(a.kind==="whale"||a.kind==="tracked"?"wn":"dn")+'">!</span><div><b class="cl" data-k="'+esc(a.key)+'">'+esc(a.sym)+"</b> "+pill("neutral",a.kind)+" "+esc(a.text)+'<div class="fe">'+clk(a.t)+(a.ev&&a.ev.tx?' · <a href="#" data-tx="'+esc(a.ev.tx)+'" data-chain="'+esc(a.chain)+'">explorer</a>':"")+"</div></div></div>";

/* ---------- view skeletons and bodies ---------- */
function coinBar(){const opts=(cur&&!ST.coins.find(c=>c.key===cur)?'<option value="'+esc(cur)+'">'+esc(cur.split(":")[1].slice(0,8))+"</option>":"")+ST.coins.map(c=>'<option value="'+esc(c.key)+'">'+esc(c.sym)+" ("+esc(c.chain)+")</option>").join("");
 return '<div class="card"><div class="row"><div><label for="csel">Selected coin</label><select id="csel"><option value="">Choose a coin…</option>'+opts+'</select></div><div class="fit"><button type="button" class="sec" id="cref">Reload</button></div></div></div>'}
function skel(v){if(SCOPED.includes(v))return coinBar()+'<div id="vbody"></div>';
 if(v==="coins")return '<div class="card"><form id="sf" class="row"><div style="flex:3"><label for="sq">Search token name, symbol or address (DexScreener)</label><input id="sq" maxlength="60" placeholder="e.g. bonk"></div><button type="submit" class="fit">Search</button><button type="button" class="sec fit" id="sclr">Clear</button></form><div class="grid g3"><div><label for="fc">Chain</label><select id="fc"></select></div><div><label for="fl">Min liquidity</label><select id="fl">'+[[0,"Any"],[10000,"$10K"],[25000,"$25K"],[100000,"$100K"],[500000,"$500K"]].map(x=>'<option value="'+x[0]+'">'+x[1]+"</option>").join("")+'</select></div><div><label for="fr">Risk tally</label><select id="fr"><option value="101">Any</option><option value="29">Low only</option><option value="54">Up to medium</option></select></div></div><label class="ck"><input type="checkbox" id="fw"> Watchlist only</label></div><div class="card" id="vbody"></div>';
 if(v==="wallets")return '<div class="card"><h2>Wallet search</h2><form id="wf" class="row"><div style="flex:3"><label for="wa">Wallet address</label><input id="wa" maxlength="100" autocomplete="off" placeholder="paste an address"></div><div><label for="wc">Chain</label><select id="wc">'+chainOpts("solana")+'</select></div><button type="submit" class="fit">Search</button></form><div class="s mu">Solana wallets also show recent on-chain signatures via your Solana RPC. Other chains show only trades this app has fetched.</div></div><div class="card"><h2>Add wallet to tracker</h2><form id="wadd" class="row"><div style="flex:3"><label for="wa2">Address</label><input id="wa2" maxlength="100" autocomplete="off"></div><div><label for="wc2">Chain</label><select id="wc2">'+chainOpts("solana")+'</select></div><div><label for="wl2">Label (optional)</label><input id="wl2" maxlength="40"></div><button type="submit" class="fit">Track</button></form></div><div id="vbody"></div>';
 if(v==="settings")return"";return '<div id="vbody"></div>'}
function chainOpts(sel){return["solana","ethereum","base","bsc","arbitrum","polygon","avalanche","optimism"].map(c=>'<option'+(c===sel?" selected":"")+">"+c+"</option>").join("")}
const BODY={};
BODY.market=()=>{const o=ST.overview,el=$("#vbody");let h="";
 if(!o||!o.n){el.innerHTML='<div class="card">'+(ST.cycle.n?"No tokens with fresh data yet. "+esc((ST.cycle.errors||[]).join(" | ")):'<span class="spin"></span> Loading the first data cycle…')+"</div>";return}
 h+='<div class="banner">Scope: '+o.n+" tokens with fresh data on "+Object.keys(o.chains).length+" chain(s) ("+Object.entries(o.chains).map(e=>esc(e[0])+" "+e[1]).join(", ")+"). They come from DexScreener boosted/profile lists, Solana new-pool discovery, your watchlist and the coin you are viewing. This is a biased sample, <b>not the whole market</b>.</div>";
 h+='<div class="card"><h2>Observed momentum '+pill(o.regime==="insufficient"?"no_data":o.regime,o.regime==="insufficient"?"not enough data":o.regime)+"</h2>"+pv("live","DexScreener · "+ago(o.ts))+'<div class="s mu">'+esc(o.why)+'</div><div class="grid g4" style="margin-top:8px">'+
  [["Rising / falling 1h",o.rise_h1+" / "+o.fall_h1],["Rising / falling 24h",o.rise_h24+" / "+o.fall_h24],["Median 1h",o.med_h1==null?"N/A":o.med_h1.toFixed(1)+"%"],["Median 24h",o.med_h24==null?"N/A":o.med_h24.toFixed(1)+"%"],["24h volume (sum)",fu(o.vol24)],["Liquidity (sum)",fu(o.liq)],["Last hour vs 24h hourly avg",o.vol_ratio==null?"N/A":o.vol_ratio.toFixed(2)+"x"],["Median liquidity change",o.liq_chg_med==null?"building history":(o.liq_chg_med>=0?"+":"")+o.liq_chg_med.toFixed(1)+"% ("+o.liq_chg_n+")"]].map(x=>'<div class="kv"><span>'+x[0]+"</span><b>"+x[1]+"</b></div>").join("")+"</div>"+
  '<div class="s mu" style="margin-top:6px">Liquidity change is '+pv("local","collected by this app")+"</div></div>";
 h+='<div class="card"><h2>Active alerts ('+ST.alerts.length+")</h2>"+(ST.alerts.length?ST.alerts.slice(0,6).map(alertRow).join(""):'<div class="mu s">No alerts yet. Alerts are raised for unusual volume, liquidity drops, large trades, suspected bot patterns and tracked-wallet trades.</div>')+"</div>";
 h+='<div class="row" style="margin-bottom:8px"><button type="button" class="'+(gw==="h1"?"":"sec")+'" data-gw="h1">Movers 1h</button><button type="button" class="'+(gw==="h24"?"":"sec")+'" data-gw="h24">Movers 24h</button></div>';
 h+=mlist("Top gainers ("+gw+")",o["gain_"+gw],gw)+mlist("Top losers ("+gw+")",o["lose_"+gw],gw)+mlist("Unusual volume (last hour 3x+ the 24h hourly average)",o.unusual,"h1","No monitored token meets the 3x threshold.")+mlist("New pairs (under 24h old)",o.new,"h1","No new pairs among monitored tokens.");
 h+='<div class="card"><h2>AI market analysis</h2>'+(ST.ai.configured?'<button type="button" id="aimkt">'+(ST.ai.busy?"Running…":"Run AI market analysis")+'</button><div class="s mu">One paid API call to '+esc(ST.ai.provider)+". The model sees only the summary above.</div>":'<div><b>AI API NOT CONFIGURED</b><div class="s mu">Add a key in Settings. All other analytics keep working.</div></div>')+"</div>"+aiCard(ST.ai.history.find(r=>r.kind==="market"));
 h+='<div class="card s mu">Cycle '+ST.cycle.n+" took "+ST.cycle.ms+" ms, refresh every "+ST.settings.refresh_s+"s. "+(ST.cycle.errors&&ST.cycle.errors.length?'<span class="wn">'+esc(ST.cycle.errors.join(" | "))+"</span>":"")+"</div>";el.innerHTML=h};
BODY.pump=()=>{const a=ST.coins.filter(c=>c.pump).sort((x,y)=>(x.age_h==null?1e9:x.age_h)-(y.age_h==null?1e9:y.age_h));
  const pct=(v)=>v==null?'N/A':(v>0?'+':'')+Number(v).toFixed(2)+'%';
  const change=(v)=>'<span class="'+(v==null?'mu':v>0?'up':v<0?'dn':'mu')+'">'+pct(v)+'</span>';
  $("#vbody").innerHTML='<div class="card"><h2>Pump.fun live board</h2><div class="s mu">Coin thumbnails, price changes and AI review timetable. Price data updates when the connected market source publishes a new snapshot; this is not a guaranteed one-second trade stream. Pump.fun identification is inferred from public DEX metadata, not an official Pump.fun feed.</div></div>'+
  '<div class="card"><h3>AI review timetable</h3><div class="tw"><table><thead><tr><th>Stage</th><th>Expected timing</th><th>What it means</th></tr></thead><tbody><tr><td>Market refresh</td><td>About every '+esc(String(ST.settings.refresh_s))+' sec</td><td>Refreshes the app snapshot; source data may be older</td></tr><tr><td>New token discovery</td><td>Usually 30–90+ sec</td><td>Depends on DexScreener/GeckoTerminal surfacing the pool</td></tr><tr><td>AI deep review</td><td>Usually ~10–45 sec after you start it</td><td>Open a coin → Details → Run AI analysis; provider/network can take longer</td></tr><tr><td>Confirmation</td><td>Only when evidence meets rules</td><td>Otherwise WAIT FOR CONFIRMATION / AVOID HIGH RISK / INSUFFICIENT DATA</td></tr></tbody></table></div><div class="s mu">These are estimates, not a countdown or profit guarantee. The app cannot promise a coin will pump or deliver confirmation by a fixed time.</div></div>'+
  '<div class="card"><h2>Detected launches ('+a.length+')</h2>'+(a.length?'<div class="coin-grid">'+a.map(c=>'<div class="coin-tile r" tabindex="0" data-k="'+esc(c.key)+'"><div class="coin-head">'+(c.logo?'<img class="coin-photo" src="'+esc(c.logo)+'" alt="'+esc(c.sym)+' logo" loading="lazy" onerror="this.style.display=\'none\'">':'<div class="coin-photo coin-placeholder">◉</div>')+'<div class="coin-meta"><b>'+esc(c.sym)+'</b><div class="s mu">'+esc(c.name||c.chain||'Token')+'</div><div class="s mu">'+esc(c.chain||'')+'</div></div></div><div class="coin-price">'+fp(c.price)+'</div><div class="coin-changes"><span>5m '+change(c.chg&&c.chg.m5)+'</span><span>1h '+change(c.chg&&c.chg.h1)+'</span><span>24h '+change(c.chg&&c.chg.h24)+'</span></div><div class="coin-stats"><span>Liquidity <b>'+fu(c.liq)+'</b></span><span>Vol 24h <b>'+fu(c.vol24)+'</b></span><span>Txns 1h <b>'+(c.tx1h||'N/A')+'</b></span></div><div class="coin-verdict">'+cb(c.concl)+'</div><div class="s mu">'+esc(c.pump&&c.pump.status||'Pump.fun-related (inferred)')+'</div></div>').join('')+'</div>':'<div class="mu">No Pump.fun-related tokens detected yet. Keep discovery enabled; new pools appear when the connected public sources surface them.</div>')+'</div>'};BODY.coins=()=>{let a=searchRes!==null?searchRes:ST.coins;const q=$("#fc");if(q&&q.dataset.n!==String(ST.coins.length)){q.dataset.n=String(ST.coins.length);q.innerHTML='<option value="">All</option>'+[...new Set(ST.coins.map(c=>c.chain))].sort().map(c=>'<option'+(Fl.chain===c?" selected":"")+">"+esc(c)+"</option>").join("")}
 a=a.filter(c=>(!Fl.chain||c.chain===Fl.chain)&&(c.liq||0)>=Fl.minliq&&(c.risk==null||c.risk<=Fl.maxrisk)&&(!Fl.watch||c.watch));
 $("#vbody").innerHTML=(searchRes!==null?'<div class="s mu" style="margin-bottom:6px">Search results for “'+esc(searchQ)+'” '+pv("live","DexScreener search")+"</div>":'<div class="s mu" style="margin-bottom:6px">'+a.length+" monitored coins "+pv("live","DexScreener")+" · tap a header to sort, tap a row to open</div>")+coinTable(sortedCoins(a),ST.coins.length?"No coins match these filters.":"Waiting for the first data cycle.")};
let searchRes=null,searchQ="";
BODY.watch=()=>{const a=ST.coins.filter(c=>c.watch);$("#vbody").innerHTML='<div class="card"><h2>Watchlist ('+a.length+")</h2>"+coinTable(sortedCoins(a),"Your watchlist is empty. Tap ☆ on any coin. Watched coins are refreshed every cycle and get transaction and candle data fetched in rotation.")+"</div>"};
function needCoin(){return '<div class="card"><h2>No coin selected</h2><div class="mu">Choose a coin in the selector above, or open one from <a href="#" data-go="coins">Coin Explorer</a>.</div></div>'}
function stateBar(c){return pv("live","DexScreener · "+ago(c.updated))+(c.stale?'<span class="pill b-bearish">STALE: do not rely on this price</span>':"")+(c.mon?"":'<span class="pill b-neutral">not auto-refreshed: press Reload</span>')}
BODY.details=()=>{const el=$("#vbody");if(!cur)return el.innerHTML=needCoin();if(busy&&!D)return el.innerHTML='<div class="card"><span class="spin"></span> Loading…</div>';if(!D)return el.innerHTML='<div class="card dn">'+esc(errMsg||"No data")+"</div>";
 const d=D,c=d.coin,a=d.analysis,cons=a.consensus,rk=a.risk;let h='<div class="card"><div class="row" style="align-items:center"><div style="flex:3" class="coin">'+(c.logo?'<img src="'+esc(c.logo)+'" alt="" style="width:40px;height:40px">':"")+'<div><h2 style="margin:0;color:var(--tx);text-transform:none;font-size:18px">'+esc(c.sym)+' <span class="pill">'+esc(c.chain)+"</span>"+(c.pump?' <span class="pill b-neutral">Pump.fun?</span>':"")+'</h2><div class="s mu">'+esc(c.name||"N/A")+"</div></div></div>"+cb(cons.conclusion)+'<button type="button" class="star'+(d.watch?" on":"")+'" data-act="watch" data-k="'+esc(c.key)+'" aria-label="Toggle watchlist">'+(d.watch?"★":"☆")+"</button></div>"+
  '<div class="num" style="font-size:22px;margin:6px 0">$'+fp(c.price)+'</div><div class="grid g4">'+[["m5","5m"],["h1","1h"],["h6","6h"],["h24","24h"]].map(x=>'<div class="kv"><span>'+x[1]+"</span><b>"+fc(c.chg[x[0]])+"</b></div>").join("")+'</div><div style="margin-top:6px">'+stateBar(c)+"</div>"+d.warnings.map(w=>'<div class="s '+(w.indexOf("stale")>=0?"wn":"mu")+'">⚠ '+esc(w)+"</div>").join("")+
  '<div class="row" style="margin-top:8px"><button type="button" class="sec sm" data-go="candles">Candlesticks</button><button type="button" class="sec sm" data-go="txns">Transactions</button><button type="button" class="sec sm" data-go="bots">Bot patterns</button><button type="button" class="sec sm" data-go="core">Agent core</button><button type="button" class="sec sm" data-go="signal">Signal report</button></div></div>';
 h+='<div class="card"><h2>Valuation, liquidity and flow</h2><div class="grid g3">'+[["Market cap (reported)",fu(c.mcap)],["FDV (fully diluted ≠ market cap)",fu(c.fdv)],["Liquidity",fu(c.liq)],["Volume 24h",fu(c.vol.h24)],["Pair age",fa(c.age_h)],["DEX / quote",esc((c.dex||"N/A")+" / "+(c.quote&&c.quote.sym||"N/A"))]].map(x=>'<div class="kv"><span>'+x[0]+"</span><b>"+x[1]+"</b></div>").join("")+"</div>"+
  '<div class="tw"><table><thead><tr><th></th><th>5m</th><th>1h</th><th>6h</th><th>24h</th></tr></thead><tbody><tr><td>Volume</td>'+["m5","h1","h6","h24"].map(w=>"<td>"+fu(c.vol[w])+"</td>").join("")+"</tr><tr><td>Buys (count)</td>"+["m5","h1","h6","h24"].map(w=>"<td>"+(c.tx[w].buys==null?"N/A":c.tx[w].buys)+"</td>").join("")+"</tr><tr><td>Sells (count)</td>"+["m5","h1","h6","h24"].map(w=>"<td>"+(c.tx[w].sells==null?"N/A":c.tx[w].sells)+"</td>").join("")+"</tr></tbody></table></div>"+
  '<div class="s mu" style="margin-top:6px">DexScreener supplies buy/sell <b>counts</b>, not buy/sell dollar volume. Fetch transactions for observed dollar flow.<br>Pool: '+esc(c.pair||"N/A")+"<br>Token: "+esc(c.addr)+'</div><div class="row" style="margin-top:6px">'+(d.explorer?'<a href="'+esc(d.explorer)+'" target="_blank" rel="noopener noreferrer">Block explorer</a>':'<span class="mu s">No explorer link for this chain</span>')+(c.url?'<a href="'+esc(c.url)+'" target="_blank" rel="noopener noreferrer">DexScreener page</a>':"")+"</div>"+
  (c.links&&c.links.length?'<div class="s mu" style="margin-top:6px">Project-listed links (unverified, may be impersonation): '+c.links.map(l=>'<a href="'+esc(l[1])+'" target="_blank" rel="noopener noreferrer">'+esc(l[0])+"</a>").join(" · ")+"</div>":"")+(c.pump?'<div class="s wn" style="margin-top:6px">Pump.fun: '+esc(c.pump.status)+" ("+esc(c.pump.evidence.join("; "))+"). "+esc(c.pump.note)+"</div>":"")+"</div>";
 h+='<div class="card"><h2>Price: locally collected history</h2>'+pv("local","snapshots taken by this app since it started")+'<canvas id="mini" style="height:150px"></canvas><div class="s mu">Not exchange history. Open Candlestick Analysis for provider OHLCV candles.</div></div>';
 h+='<div class="card"><h2>Risk indicators '+pill(rk.level==="high"?"bearish":rk.level==="medium"?"neutral":"bullish","tally "+(rk.risk==null?"N/A":rk.risk)+"/100 "+rk.level)+"</h2><div class=\"s mu\">"+esc(rk.summary)+"</div>"+findings(rk)+(rk.hard&&rk.hard.length?'<div class="dn s">Blocking flags: '+esc(rk.hard.join("; "))+"</div>":"")+
  "<h3>Could not be checked with the connected sources</h3>"+list(rk.missing)+(d.onchain?"<h3>Holder concentration "+pv("cached","Solana RPC · "+ago(d.onchain.fetched))+'</h3><div class="s">Top 1: '+d.onchain.top1_pct.toFixed(1)+"% · Top 5: "+d.onchain.top5_pct.toFixed(1)+"% · Top 10: "+d.onchain.top10_pct.toFixed(1)+'%</div><div class="s mu">'+esc(d.onchain.caveat)+"</div>":"")+
  (c.chain==="solana"?'<button type="button" class="sec sm" id="holders" style="margin-top:6px">Holder check (Solana RPC)</button>':'<div class="s mu">Holder concentration is only supported for Solana tokens.</div>')+"</div>";
 if(d.missing.length)h+='<div class="card"><h2>Missing data</h2>'+list(d.missing)+"</div>";el.innerHTML=h;const m=$("#mini");if(m)drawLocal(m,d.session.map(p=>[p[0],p[1]]))};
BODY.candles=()=>{const el=$("#vbody");if(!cur)return el.innerHTML=needCoin();
 let h='<div class="card"><div class="row">'+["1m","5m","15m","1h","4h","1D"].map(t=>'<button type="button" class="fit '+(tf===t?"":"sec")+'" data-tf="'+t+'">'+t+"</button>").join("")+"</div>"+
  '<div class="row">'+[["ema","EMA 20"],["sma","SMA 50"],["vol","Volume"],["rsi","RSI"],["macd","MACD"],["sr","Support/Res."]].map(x=>'<label class="ck fit"><input type="checkbox" data-ind="'+x[0]+'"'+(IND[x[0]]?" checked":"")+"> "+x[1]+"</label>").join("")+"</div></div>";
 if(busy&&!CD)h+='<div class="card"><span class="spin"></span> Loading candles…</div>';
 else if(!CD)h+='<div class="card dn">'+esc(errMsg||"No data")+"</div>";
 else if(!CD.ok)h+='<div class="card"><h2>Candlesticks unavailable</h2><div class="wn s">'+esc(CD.error)+"</div><div class=\"s mu\">"+esc(CD.source)+'</div><canvas id="cvl" style="height:180px"></canvas></div>';
 else{const T=CD.tech;h+='<div class="card"><h2>'+esc(CD.n)+" candles · "+esc(CD.tf)+"</h2>"+pv("cached","provider OHLCV · "+ago(CD.fetched))+(T?pv("est","indicators calculated by this app"):"")+'<canvas id="cvp" style="height:300px"></canvas><div class="s mu" id="tip">Tap the chart for candle details.</div>'+(T&&IND.rsi?'<canvas id="cvr" style="height:90px;margin-top:6px"></canvas>':"")+(T&&IND.macd?'<canvas id="cvm" style="height:100px;margin-top:6px"></canvas>':"")+
  '<div class="s mu" style="margin-top:6px">Legend: <span style="color:var(--cy)">EMA20</span> · <span style="color:var(--wn)">SMA50</span> · dashed green/red = estimated support/resistance. '+esc(CD.source)+"</div></div>";
  if(T){h+='<div class="card"><h2>Detected signals (calculated)</h2>'+(T.signals.length?T.signals.map(s=>'<div class="f"><span class="fi '+(s.dir==="pos"?"up":s.dir==="neg"?"dn":"mu")+'">'+(s.dir==="pos"?"+":s.dir==="neg"?"−":"·")+"</span><div>"+esc(s.text)+'<div class="fe">Calculated from the last '+esc(CD.n)+" candles. "+esc(s.type)+"</div></div></div>").join(""):'<div class="mu s">No signal fired.</div>')+
   "<h3>Support / resistance estimates</h3><div class=\"s\">Support: "+(T.support.length?T.support.map(s=>"$"+fp(s.level)+" ("+s.touches+" touches)").join(", "):"none found")+"<br>Resistance: "+(T.resistance.length?T.resistance.map(s=>"$"+fp(s.level)+" ("+s.touches+" touches)").join(", "):"none found")+'</div><div class="s mu">'+esc(T.note)+"</div></div>"}else h+='<div class="card mu s">'+esc(CD.note||"No indicators.")+"</div>"}
 el.innerHTML=h;
 if(CD&&CD.ok){const p=$("#cvp");if(p)drawCandles(p,CD);if(CD.tech){const r=$("#cvr"),m=$("#cvm");if(r)drawRSI(r,CD);if(m)drawMACD(m,CD)}}else if(CD){const l=$("#cvl");if(l)drawLocal(l,CD.session)}};
function txRow(r,sym){return "<tr><td>"+ago(r.t)+"</td>"+(sym?"<td><b class=\"cl\" data-k=\""+esc(r.key)+'">'+esc(r.sym)+"</b></td>":"")+'<td class="'+(r.kind==="buy"?"up":"dn")+'">'+r.kind.toUpperCase()+'</td><td class="num">$'+Math.round(r.usd).toLocaleString()+'</td><td class="num">'+(r.amt==null?"N/A":r.amt.toLocaleString(undefined,{maximumFractionDigits:2}))+"</td><td>"+(r.wlink?'<a href="'+esc(r.wlink)+'" target="_blank" rel="noopener noreferrer">'+esc(sh(r.wallet))+"</a>":esc(sh(r.wallet)))+(r.tracked?' <span class="pill b-neutral">tracked</span>':"")+"</td><td>"+(r.link?'<a href="'+esc(r.link)+'" target="_blank" rel="noopener noreferrer">tx</a>':"N/A")+"</td></tr>"}
BODY.txns=()=>{const el=$("#vbody");
 let h='<div class="card"><div class="row"><button type="button" class="fit '+(feedMode?"sec":"")+'" data-fm="0">This coin</button><button type="button" class="fit '+(feedMode?"":"sec")+'" data-fm="1">All fetched coins</button><div><label for="sidef">Side</label><select id="sidef">'+["all","buy","sell"].map(x=>'<option'+(x===sideF?" selected":"")+">"+x+"</option>").join("")+'</select></div><div><label for="minf">Min USD</label><select id="minf">'+[0,100,500,1000,5000].map(x=>'<option value="'+x+'"'+(x===minF?" selected":"")+">"+(x?"$"+x:"Any")+"</option>").join("")+"</select></div>"+(feedMode?"":'<button type="button" class="fit" id="fetchtx">Fetch latest now</button>')+"</div></div>";
 if(feedMode){if(!FEED)h+='<div class="card"><span class="spin"></span> Loading…</div>';else{const rows=FEED.rows.filter(r=>(sideF==="all"||r.kind===sideF)&&r.usd>=minF);h+='<div class="card"><h2>Live transactions across fetched coins ('+rows.length+")</h2>"+pv("cached","GeckoTerminal pool trades")+'<span class="s mu"> '+FEED.coins_with_trades+" coins have trade data. Only watchlist and viewed coins are fetched (rate limits).</span>"+(rows.length?'<div class="tw"><table><thead><tr><th>Time</th><th>Coin</th><th>Side</th><th>USD (est.)</th><th>Tokens</th><th>Wallet</th><th>Tx</th></tr></thead><tbody>'+rows.slice(0,150).map(r=>txRow(r,true)).join("")+"</tbody></table></div>":'<div class="mu">No trades fetched yet. Open a coin, add coins to the watchlist, or press Fetch on a coin.</div>')+"</div>"}}
 else if(!cur)h+=needCoin();
 else if(busy&&!TV)h+='<div class="card"><span class="spin"></span> Loading…</div>';
 else if(!TV)h+='<div class="card dn">'+esc(errMsg||"No data")+"</div>";
 else{const rows=TV.rows.filter(r=>(sideF==="all"||r.kind===sideF)&&r.usd>=minF),an=TV.analysis;
  if(!TV.tx_ok)h+='<div class="card wn">Transaction data is not available for this chain or pool from the connected provider.</div>';
  else if(!TV.rows.length)h+='<div class="card"><h2>No transactions fetched yet</h2><div class="mu s">'+esc(TV.error||"Press “Fetch latest now”. Watchlist and viewed coins are fetched automatically within rate limits.")+"</div></div>";
  else{h+='<div class="card"><h2>'+esc(TV.sym)+" transactions</h2>"+pv("cached","GeckoTerminal pool trades · fetched "+ago(TV.fetched))+pv("est","USD value is the provider's estimate")+'<div class="s mu">'+an.n+" trades observed "+esc(clk(an.t0))+" to "+esc(clk(an.t1))+" ("+((an.t1-an.t0)/60).toFixed(0)+" min). "+esc(TV.source)+'</div><div class="grid g4" style="margin-top:6px">'+[["Buys",an.buy_n+" · "+fu(an.buy_usd)],["Sells",an.sell_n+" · "+fu(an.sell_usd)],["Net flow",(an.net_usd>=0?"+":"-")+fu(Math.abs(an.net_usd))],["Wallets",an.n_wallets]].map(x=>'<div class="kv"><span>'+x[0]+"</span><b>"+x[1]+"</b></div>").join("")+"</div>"+(TV.error?'<div class="wn s">Last refresh error: '+esc(TV.error)+"</div>":"")+"</div>";
   if(an.large.length)h+='<div class="card"><h2>Large trades (≥ $'+Math.round(an.whale_usd).toLocaleString()+(an.whale_liq_usd?" or $"+Math.round(an.whale_liq_usd).toLocaleString()+" = share of liquidity":"")+")</h2>"+'<div class="tw"><table><thead><tr><th>Time</th><th>Side</th><th>USD (est.)</th><th>Tokens</th><th>Wallet</th><th>Tx</th></tr></thead><tbody>'+an.large.map(r=>txRow(r,false)).join("")+"</tbody></table></div></div>";
   h+='<div class="card"><h2>Recent trades ('+rows.length+")</h2>"+(rows.length?'<div class="tw"><table><thead><tr><th>Time</th><th>Side</th><th>USD (est.)</th><th>Tokens</th><th>Wallet</th><th>Tx</th></tr></thead><tbody>'+rows.slice(0,120).map(r=>txRow(r,false)).join("")+"</tbody></table></div>":'<div class="mu s">No trades match the filters.</div>')+"</div>"}}
 el.innerHTML=h};
BODY.bots=()=>{const el=$("#vbody");if(!cur)return el.innerHTML=needCoin();if(busy&&!TV)return el.innerHTML='<div class="card"><span class="spin"></span> Loading…</div>';if(!TV)return el.innerHTML='<div class="card dn">'+esc(errMsg||"No data")+"</div>";
 const b=TV.bot,an=TV.analysis;let h='<div class="card"><h2>Bot pattern analysis: '+esc(TV.sym)+" "+sg(b.signal)+"</h2>"+(an?pv("cached","GeckoTerminal pool trades · "+an.n+" trades · "+clk(an.t0)+" to "+clk(an.t1)+" · fetched "+ago(TV.fetched)):'<span class="pill b-no_data">no transaction data fetched</span>')+'<div class="s mu" style="margin-top:6px">'+esc(b.summary)+"</div>"+
  (TV.tx_ok?'<button type="button" class="sm" id="fetchtx" style="margin-top:6px">Fetch latest trades and re-analyse</button>':'<div class="wn s">Transactions are unavailable for this chain/pool.</div>')+'<div class="banner" style="margin-top:8px">A trading pattern cannot prove a bot exists. Findings are statistical heuristics labelled “Suspected automated pattern”; they never identify an operator, and they cannot see private strategies.</div></div>';
 h+='<div class="card"><h2>Findings and evidence</h2>'+findings(b)+"<h3>Not checked</h3>"+list(b.missing)+"</div>";
 if(an){h+='<div class="card"><h2>Suspected automated wallets ('+an.suspected.length+")</h2>"+(an.suspected.length?'<div class="tw"><table><thead><tr><th>Wallet</th><th>Trades</th><th>USD (est.)</th><th>Label</th><th>Evidence (flags)</th><th></th></tr></thead><tbody>'+an.suspected.map(s=>"<tr><td>"+(s.wlink?'<a href="'+esc(s.wlink)+'" target="_blank" rel="noopener noreferrer">'+esc(sh(s.wallet))+"</a>":esc(sh(s.wallet)))+"</td><td>"+s.n+"</td><td>"+fu(s.usd)+"</td><td>"+esc(s.label)+'<br><span class="mu s">confidence '+esc(s.confidence)+'</span></td><td class="wrap">'+esc(s.flags.join("; "))+'</td><td><button type="button" class="sec sm" data-addw="'+esc(s.wallet)+'" data-chain="'+esc(TV.chain)+'">Track</button></td></tr>').join("")+"</tbody></table></div>":'<div class="mu s">No wallet matched two or more statistical flags in this window.</div>')+"</div>";
  const cl=(t,a)=>a.length?"<h3>"+t+"</h3>"+a.map(c=>'<div class="s">'+c.n_wallets+" wallets, similar size (~$"+Math.round(c.usd).toLocaleString()+") within 10 seconds, seen "+c.occurrences+"×. Wallets: "+esc(c.wallets.map(sh).join(", "))+"</div>").join(""):"";
  h+='<div class="card"><h2>Possible coordinated activity</h2>'+(an.cluster_buys.length||an.cluster_sells.length?cl("Buying",an.cluster_buys)+cl("Selling",an.cluster_sells)+'<div class="s mu">Similar timing and size does not establish common ownership: this app does not retrieve wallet funding history.</div>':'<div class="mu s">No repeated tight-timing, similar-size clusters of 3+ wallets.</div>')+"</div>";
  h+='<div class="card"><h2>Concentration</h2><div class="s">Top 3 wallets account for '+an.top3_share_pct.toFixed(0)+"% of observed volume.</div>"+'<div class="tw"><table><thead><tr><th>Wallet</th><th>Trades</th><th>USD (est.)</th><th>Share</th></tr></thead><tbody>'+an.top_wallets.map(w=>"<tr><td>"+(w.wlink?'<a href="'+esc(w.wlink)+'" target="_blank" rel="noopener noreferrer">'+esc(sh(w.wallet))+"</a>":esc(sh(w.wallet)))+"</td><td>"+w.n+"</td><td>"+fu(w.usd)+"</td><td>"+w.share_pct.toFixed(0)+"%</td></tr>").join("")+'</tbody></table></div><div class="s mu">'+esc(an.caveat)+"</div></div>"}
 const al=ST.alerts.filter(a=>a.kind==="bot");h+='<div class="card"><h2>Bot alerts (all coins)</h2>'+(al.length?al.slice(0,8).map(alertRow).join(""):'<div class="mu s">None.</div>')+"</div>";el.innerHTML=h};
function wallets(){const w=ST.wallets;return '<div class="card"><h2>Tracked wallets ('+w.length+")</h2>"+(w.length?w.map(x=>'<div class="f"><div style="flex:1"><b>'+esc(x.label||"(no label)")+'</b> <span class="pill">'+esc(x.chain)+'</span><div class="s mu num">'+esc(x.addr)+'</div></div><button type="button" class="sec sm" data-openw="'+esc(x.addr)+'" data-chain="'+esc(x.chain)+'">Open</button><button type="button" class="bad sm" data-rmw="'+esc(x.addr)+'">Remove</button></div>').join(""):'<div class="mu s">No wallets tracked. Track one from a search result or the Bot Intelligence page. Trades by tracked wallets raise alerts when they appear in fetched pools.</div>')+"</div>"}
BODY.wallets=()=>{let h=wallets();const al=ST.alerts.filter(a=>a.kind==="tracked"||a.kind==="whale");
 h+='<div class="card"><h2>Large-transaction and tracked-wallet alerts</h2>'+(al.length?al.slice(0,10).map(alertRow).join(""):'<div class="mu s">None yet. Large trades are detected in pools whose trades this app has fetched (watchlist and viewed coins).</div>')+"</div>";
 if(WP){const p=WP;h+='<div class="card"><h2>Wallet profile '+pill("neutral",p.chain)+"</h2><div class=\"num s\" style=\"overflow-wrap:anywhere\">"+esc(p.address)+"</div>"+(p.explorer?'<a href="'+esc(p.explorer)+'" target="_blank" rel="noopener noreferrer">Open on explorer</a>':"")+
  '<div class="s" style="margin-top:6px"><b>Verified facts:</b> '+esc(p.facts)+"<br><b>Estimates:</b> "+esc(p.estimates)+"</div>"+'<div class="grid g3" style="margin-top:6px">'+[["Observed trades",p.n],["Buys (est.)",fu(p.buy_usd)],["Sells (est.)",fu(p.sell_usd)]].map(x=>'<div class="kv"><span>'+x[0]+"</span><b>"+x[1]+"</b></div>").join("")+"</div>"+(p.coins.length?'<div class="s mu">Coins seen: '+esc(p.coins.join(", "))+"</div>":"")+
  list(p.limits,"mu s")+"</div>";
  h+='<div class="card"><h2>Activity timeline</h2>'+(p.observed.length?'<div class="tw"><table><thead><tr><th>Time</th><th>Coin</th><th>Side</th><th>USD (est.)</th><th>Tx</th></tr></thead><tbody>'+p.observed.map(r=>"<tr><td>"+esc(when(r.t))+'</td><td><b class="cl" data-k="'+esc(r.key)+'">'+esc(r.sym)+'</b></td><td class="'+(r.kind==="buy"?"up":"dn")+'">'+r.kind.toUpperCase()+"</td><td>$"+Math.round(r.usd).toLocaleString()+"</td><td>"+(r.link?'<a href="'+esc(r.link)+'" target="_blank" rel="noopener noreferrer">tx</a>':"N/A")+"</td></tr>").join("")+"</tbody></table></div>":'<div class="mu s">No trades by this wallet in the pools fetched so far.</div>')+
   (p.solana?"<h3>Recent on-chain signatures "+pv("cached","Solana RPC · "+ago(p.solana.fetched))+"</h3><div class=\"s\">SOL balance: "+(p.solana.sol==null?"N/A":p.solana.sol.toFixed(4))+'</div><div class="tw"><table><thead><tr><th>Time</th><th>Status</th><th>Tx</th></tr></thead><tbody>'+p.solana.recent.map(s=>"<tr><td>"+esc(when(s.t))+"</td><td>"+(s.failed?'<span class="dn">failed</span>':"ok")+'</td><td><a href="'+esc(s.link||"#")+'" target="_blank" rel="noopener noreferrer">'+esc(sh(s.sig))+"</a></td></tr>").join("")+'</tbody></table></div><div class="s mu">'+esc(p.solana.note)+"</div>":"")+(p.solana_error?'<div class="wn s">Solana RPC: '+esc(p.solana_error)+"</div>":"")+"</div>"}
 $("#vbody").innerHTML=h};
BODY.core=()=>{const el=$("#vbody");if(!cur)return el.innerHTML=needCoin();if(busy&&!D)return el.innerHTML='<div class="card"><span class="spin"></span> Loading…</div>';if(!D)return el.innerHTML='<div class="card dn">'+esc(errMsg||"No data")+"</div>";
 const a=D.analysis,ids=["trend","volume","liquidity","bot","whale","risk","ai"],lab={trend:"Trend",volume:"Volume",liquidity:"Liquidity",bot:"Bot",whale:"Whale",risk:"Risk",ai:"AI"},ag={};ST.agents.forEach(x=>ag[x.id]=x);
 const sig=id=>id==="ai"?(D.ai?({"BUY SETUP TO INVESTIGATE":"bullish","AVOID / HIGH RISK":"bearish","WAIT FOR CONFIRMATION":"neutral"}[D.ai.conclusion]||"no_data"):"no_data"):a[id].signal,col={bullish:css("--up"),bearish:css("--dn"),neutral:css("--wn"),no_data:css("--mu"),error:css("--dn")};
 const pos=i=>{const t=-Math.PI/2+i*2*Math.PI/7;return[180+118*Math.cos(t),180+118*Math.sin(t)]},nid={};ids.forEach((id,i)=>nid[id]=pos(i));
 const alertN=id=>ST.alerts.filter(x=>x.key===cur&&({volume:["volume"],liquidity:["liquidity"],bot:["bot"],whale:["whale","tracked"]}[id]||[]).includes(x.kind)).length;
 let s='<svg class="core" viewBox="0 0 360 360" role="img" aria-label="Agent core: seven analysts feeding the Consensus Analyst"><defs><marker id="ar" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0,0L6,3L0,6z" fill="'+css("--mu")+'"/></marker></defs><circle cx="180" cy="180" r="150" fill="none" stroke="'+css("--ln")+'" stroke-dasharray="2 6"/>';
 (a.consensus.conflicts||[]).forEach(c=>{const m={Trend:"trend",Volume:"volume",Liquidity:"liquidity","Bot pattern":"bot","Whale/wallet":"whale",Risk:"risk"},p=nid[m[c[0]]],q=nid[m[c[1]]];if(p&&q)s+='<line x1="'+p[0]+'" y1="'+p[1]+'" x2="'+q[0]+'" y2="'+q[1]+'" stroke="'+css("--dn")+'" stroke-width="1.5" stroke-dasharray="3 3"/>'});
 ids.forEach(id=>{const p=nid[id],sg=sig(id),run=ag[id]&&ag[id].status==="running";s+='<line x1="'+p[0]+'" y1="'+p[1]+'" x2="180" y2="180" stroke="'+col[sg]+'" stroke-width="1.6" '+(sg==="no_data"?'stroke-dasharray="3 5" opacity=".5"':(run?'class="flow" stroke-dasharray="6 6"':""))+' marker-end="url(#ar)"/>'});
 ids.forEach(id=>{const p=nid[id],sg=sig(id),st=ag[id]||{},run=st.status==="running",nc=id==="ai"&&st.status==="not_configured",n=alertN(id);
  s+='<g class="nd" data-agent="'+id+'" tabindex="0" role="button" aria-label="'+lab[id]+' analyst: '+(SIG[sg]||sg)+'"><circle cx="'+p[0]+'" cy="'+p[1]+'" r="26" fill="'+css("--pn2")+'" stroke="'+col[sg]+'" stroke-width="'+(agSel===id?4:2)+'" '+(nc?'stroke-dasharray="4 4"':"")+"/>"+(run?'<circle class="run" cx="'+p[0]+'" cy="'+p[1]+'" r="31" fill="none" stroke="'+css("--cy")+'" stroke-width="2" stroke-dasharray="10 12"/>':"")+'<text x="'+p[0]+'" y="'+(p[1]+4)+'" text-anchor="middle" fill="'+css("--tx")+'" font-size="11" font-weight="700">'+lab[id]+"</text>"+(n?'<circle cx="'+(p[0]+20)+'" cy="'+(p[1]-20)+'" r="8" fill="'+css("--dn")+'"/><text x="'+(p[0]+20)+'" y="'+(p[1]-16.5)+'" text-anchor="middle" font-size="10" fill="#fff">'+n+"</text>":"")+"</g>"});
 const cc=CL[a.consensus.conclusion]||CL["INSUFFICIENT DATA — NO TRADE"],cs={"c-buy":css("--up"),"c-wait":css("--wn"),"c-avoid":css("--dn"),"c-ins":css("--mu")}[cc[0]];
 s+='<g class="nd" data-agent="consensus" tabindex="0" role="button" aria-label="Consensus analyst"><circle cx="180" cy="180" r="46" fill="'+css("--pn")+'" stroke="'+cs+'" stroke-width="'+(agSel==="consensus"?5:3)+'"/><text x="180" y="170" text-anchor="middle" font-size="9" fill="'+css("--mu")+'">CONSENSUS</text><text x="180" y="184" text-anchor="middle" font-size="10" font-weight="700" fill="'+cs+'">'+esc(cc[2].split(":")[0].split(" ").slice(0,2).join(" "))+'</text><text x="180" y="198" text-anchor="middle" font-size="9" fill="'+css("--mu")+'">conf: '+esc(a.consensus.confidence.level)+"</text></g></svg>";
 let h='<div class="card"><h2>AI Agent Core: '+esc(D.coin.sym)+"</h2>"+s+'<div class="s mu" style="text-align:center">Line colour = that agent\'s finding for this coin (green supportive, red concerning, amber neutral, grey no data). Red dashed chords = agents in conflict. Red badges = active alerts. A spinning ring appears only while the agent is actually running. Tap a node for its report.</div></div>';
 const sel=ag[agSel]||{name:agSel,impl:""},res=agSel==="ai"?null:a[agSel];
 h+='<div class="card"><h2>'+esc(sel.name)+" "+pill(sel.status||"idle")+"</h2><div class=\"s mu\">"+esc(sel.impl)+"</div>"+'<div class="s" style="margin:4px 0">Last run '+ago((ag[agSel]||{}).last_run)+" · "+((ag[agSel]||{}).last_ms||0)+" ms · "+((ag[agSel]||{}).runs||0)+" runs · "+((ag[agSel]||{}).errors||0)+" errors"+((ag[agSel]||{}).last_error?' · <span class="dn">'+esc(ag[agSel].last_error)+"</span>":"")+"</div>";
 if(agSel==="ai"){h+=D.ai_configured?(D.ai?"":'<div class="mu s">No AI analysis for this coin yet.</div>')+'<button type="button" id="aigo">'+(ST.ai.busy?"Running…":"Run AI analysis for "+esc(D.coin.sym))+'</button><div class="s mu">One paid call to your provider. Data sent: this coin\'s real metrics, agent findings and transaction summary.</div>':'<div><b>AI API NOT CONFIGURED</b><div class="s mu">Add a key in Settings. Deterministic agents keep working.</div></div>'}
 else if(res){h+="<div>"+sg_(res.signal)+" "+esc(res.summary)+"</div>"+findings(res)+'<h3>Data used</h3><div class="s mu">'+esc((res.used||[]).join(", ")||"none")+"</div><h3>Unavailable</h3>"+list(res.missing)+(agSel==="consensus"?'<h3>Agree</h3><div class="s">'+esc((res.agree||[]).join(", ")||"none")+"</div><h3>Conflicts</h3>"+(res.conflicts.length?list(res.conflicts.map(x=>x.join(" vs "))):'<div class="mu s">None.</div>'):"")}
 h+="</div>"+(D.ai?aiCard(D.ai):"");
 h+='<div class="card"><h2>Activity log</h2>'+(ST.feed.length?ST.feed.slice(0,14).map(f=>'<div class="s '+esc(f.k)+'">'+clk(f.t)+"  "+esc(f.m)+"</div>").join(""):'<div class="mu s">Nothing yet.</div>')+"</div>";el.innerHTML=h};
const sg_=sg;
BODY.signal=()=>{const el=$("#vbody");if(!cur)return el.innerHTML=needCoin();if(busy&&!RP)return el.innerHTML='<div class="card"><span class="spin"></span> Building report…</div>';if(!RP)return el.innerHTML='<div class="card dn">'+esc(errMsg||"No data")+"</div>";
 const r=RP,cc=CL[r.conclusion]||CL["INSUFFICIENT DATA — NO TRADE"],pr=t=>(t.length?list(t):'<div class="mu s">None.</div>');
 let h='<div class="card concl '+cc[0]+'"><div class="s mu">SIGNAL CONFIRMATION · '+esc(r.sym)+'</div><div class="big">'+esc(r.conclusion)+'</div><div class="s" style="margin-top:6px">'+esc(r.conclusion_reason)+'</div><div class="s mu" style="margin-top:8px">Research conclusion only. Not an instruction to trade. A favourable conclusion does not mean the coin is safe or will rise. No probability of profit is computed.</div></div>';
 h+='<div class="card"><h2>9. Data freshness</h2>'+r.sources.map(s=>pv(s.kind==="unavailable"?"na":s.kind,s.name)+'<span class="s mu">'+esc(s.what)+(s.ts?" · "+when(s.ts):"")+"</span><br>").join("")+(r.stale?'<div class="pill b-bearish">Price data is STALE</div>':'<div class="s up">Price data last updated '+ago(r.data_ts)+"</div>")+"</div>";
 h+='<div class="card"><h2>1. What is happening</h2><div class="s">'+esc(r.whats_happening)+"</div></div>";
 h+='<div class="card"><h2>2. Agents: agreement and conflict</h2><div class="s"><b class="up">Supportive:</b> '+esc(r.supportive.join(", ")||"none")+'<br><b class="dn">Concerning:</b> '+esc(r.concerning.join(", ")||"none")+"<br><b>Conflicts:</b> "+esc(r.conflicts.length?r.conflicts.map(x=>x.join(" vs ")).join("; "):"none")+"</div></div>";
 h+='<div class="card"><h2>3. Supporting evidence</h2>'+Object.entries(r.evidence).map(([k,v])=>"<h3>"+esc(k)+"</h3>"+pr(v)).join("")+"</div>";
 h+='<div class="card"><h2>4. Main risks</h2>'+pr(r.negatives)+"<h3>Positive factors</h3>"+pr(r.positives)+"</div>";
 h+='<div class="card"><h2>5. Is liquidity adequate for further investigation?</h2><div class="s">'+esc(r.liquidity_adequacy)+"</div></div>";
 h+='<div class="card"><h2>6. Suspicious wallet or bot-like activity</h2><div class="s">'+esc(r.suspicious_activity)+'</div><div class="s mu">Labelled “suspected”; cannot prove automation or intent.</div></div>';
 h+='<div class="card"><h2>7. What could invalidate this</h2>'+pr(r.invalidation)+"</div>";
 h+='<div class="card"><h2>8. Missing information</h2>'+pr(r.missing)+"</div>";
 h+='<div class="card"><h2>Confidence '+pill(r.confidence.level==="high"?"bullish":r.confidence.level==="medium"?"neutral":"no_data",r.confidence.level)+"</h2><div class=\"s mu\">"+esc(r.confidence.explain)+"</div>"+"</div>";
 h+='<div class="card"><h2>Scenario view</h2><div class="s">Current evidence leans: '+pill(r.lean==="neutral"?"neutral":r.lean,r.lean)+'</div><div class="s mu">Conditions to watch (not predictions):</div>'+["bullish","neutral","bearish"].map(k=>"<h3>"+k+" scenario would be supported by</h3>"+list(r.scenarios[k])).join("")+"<h3>Catalysts (data-supported only)</h3>"+pr(r.catalysts)+"</div>";
 h+='<div class="card"><h2>AI analyst</h2>'+(ST.ai.configured?'<button type="button" id="aigo">'+(ST.ai.busy?"Running…":"Run AI analysis")+'</button><div class="s mu">Adds an independent LLM reading; a disagreement downgrades a setup to WAIT FOR CONFIRMATION.</div>':'<div><b>AI API NOT CONFIGURED</b> <span class="s mu">Everything above is deterministic Python analysis, not AI.</span></div>')+"</div>"+(r.ai?aiCard(r.ai):"");
 el.innerHTML=h+'<div class="card s mu">'+esc(r.disclaimer)+" Report generated "+when(r.generated)+".</div>"};
let SET_DRAWN=false;
function settingsHTML(){const s=ST.settings,k=ST.secrets,ni=(id,l,v,st)=>'<div><label for="s_'+id+'">'+l+'</label><input id="s_'+id+'" type="number" step="'+(st||"any")+'" value="'+esc(v)+'" inputmode="decimal"></div>';
 return '<div class="card"><h2>Data and discovery</h2><div class="row">'+ni("refresh_s","Refresh seconds (15-600)",s.refresh_s,1)+ni("max_tracked","Max tokens tracked (10-100)",s.max_tracked,1)+ni("min_liq_discovery","Min liquidity for discovered tokens ($)",s.min_liq_discovery)+'</div><label class="ck"><input type="checkbox" id="s_discovery"'+(s.discovery?" checked":"")+'> Discover tokens from DexScreener lists and Solana new pools</label><label for="s_chains">Only these chains (comma separated, blank = all)</label><input id="s_chains" value="'+esc(s.chains.join(","))+'" placeholder="solana,base">'+
 '<h3>Analysis thresholds</h3><div class="row">'+ni("min_liq","Min liquidity before risk blocks ($)",s.min_liq)+ni("min_age_h","Min pair age (hours)",s.min_age_h)+ni("whale_usd","Large-trade threshold ($)",s.whale_usd)+ni("whale_liq_pct","…or % of liquidity",s.whale_liq_pct)+ni("ai_max_age_min","AI result counts as fresh for (min)",s.ai_max_age_min)+'</div><h3>Provider budget</h3><div class="row">'+ni("trades_per_cycle","Trade fetches per cycle (0-10)",s.trades_per_cycle,1)+ni("gt_rpm","GeckoTerminal calls per minute (3-30)",s.gt_rpm,1)+'</div><div class="s mu">Keyless GeckoTerminal access is tightly rate limited; keep this at or below your plan\'s limit.</div><button type="button" id="ssave" style="margin-top:8px">Save settings</button></div>'+
 '<div class="card"><h2>AI provider '+pill(k.ai_key?"idle":"not_configured",k.ai_key?"key set":"AI API NOT CONFIGURED")+'</h2><div class="s mu">Keys are stored only on this device (meme_desk_secrets.json) and never sent back to this page.'+(k.ai_key_env?" A DESK_AI_KEY environment variable is in use.":"")+'</div><div class="row"><div><label for="s_ai_provider">Provider</label><select id="s_ai_provider"><option value="anthropic"'+(s.ai_provider==="anthropic"?" selected":"")+'>Anthropic (Claude)</option><option value="openai"'+(s.ai_provider==="openai"?" selected":"")+'>OpenAI-compatible</option></select></div><div><label for="s_ai_model">Model name</label><input id="s_ai_model" value="'+esc(s.ai_model)+'"></div></div><label for="s_ai_base">OpenAI-compatible base URL (that provider only)</label><input id="s_ai_base" value="'+esc(s.ai_base)+'"><label for="k_ai">API key (write-only)</label><input id="k_ai" type="password" autocomplete="off" placeholder="'+(k.ai_key?"saved: type to replace":"paste key")+'"><div class="row" style="margin-top:8px"><button type="button" id="ksave">Save AI settings and key</button><button type="button" class="sec" id="kclear">Remove key</button></div></div>'+
 '<div class="card"><h2>Optional data keys</h2><label for="k_cg">CoinGecko demo key (raises GeckoTerminal limits) '+pill(k.cg_key?"idle":"no_data",k.cg_key?"set":"not set")+'</label><input id="k_cg" type="password" autocomplete="off" placeholder="paste key"><div class="row" style="margin-top:6px"><button type="button" class="sec" id="cgsave">Save</button><button type="button" class="sec" id="cgclear">Remove</button></div>'+
 '<label for="k_rpc">Solana RPC URL, may contain a key (using '+esc(k.sol_rpc_host)+')</label><input id="k_rpc" type="password" autocomplete="off" placeholder="https://..."><div class="row" style="margin-top:6px"><button type="button" class="sec" id="rsave">Save</button><button type="button" class="sec" id="rclear">Use public RPC</button></div></div>'+
 '<div class="card"><h2>API status and capabilities</h2><div id="provbox"></div></div><div class="card"><button type="button" class="bad" id="stop">Stop server</button></div>'}
function provHTML(){return '<div class="tw"><table><thead><tr><th>Provider</th><th>Status</th><th>Last OK</th><th>Calls</th><th>Errors</th><th>Limit</th></tr></thead><tbody>'+ST.providers.map(p=>"<tr><td class=\"wrap\">"+esc(p.name)+(p.last_error?'<div class="dn s">'+esc(p.last_error)+"</div>":"")+"</td><td>"+pill(p.status)+(p.blocked_s?" "+p.blocked_s+"s":"")+"</td><td>"+ago(p.last_ok)+"</td><td>"+p.calls+"</td><td>"+p.errors+"</td><td>"+p.rpm_limit+"/min</td></tr>").join("")+'</tbody></table></div><h3>What each source provides</h3><div class="tw"><table><thead><tr><th>Source</th><th>Provides</th><th>Key</th><th>Tier / limits</th></tr></thead><tbody>'+ST.caps.map(c=>'<tr><td class="wrap"><b>'+esc(c.name)+"</b><br>"+pill(c.status)+'</td><td class="wrap">'+esc(c.provides)+'</td><td class="wrap">'+esc(c.key)+'</td><td class="wrap">'+esc(c.tier)+"</td></tr>").join("")+'</tbody></table></div><div class="s mu">Limits and terms change: check each provider\'s current documentation before relying on them.</div>'}

/* ---------- loading and rendering ---------- */
async function loadFor(v,force){const my=++sess;if(!SCOPED.includes(v))return;if(v==="txns"&&feedMode){try{FEED=await api("/api/feed")}catch(e){errMsg=e.message}return render()}
 if(!cur)return;busy=true;errMsg="";const k=encodeURIComponent(cur||"");
 try{if(v==="details"||v==="core")D=await api("/api/coin?key="+k+(force?"&refresh=1":""));
  else if(v==="candles")CD=await api("/api/candles?key="+k+"&tf="+tf);
  else if(v==="txns"||v==="bots")TV=await api("/api/trades?key="+k+(force?"&fetch=1":""));
  else if(v==="signal"){RP=await api("/api/report?key="+k);if(!D||D.coin.key!==cur)D=await api("/api/coin?key="+k)}
  if(v==="core"&&!D)errMsg="No data"}catch(e){errMsg=e.message;if(my===sess){if(v==="details"||v==="core")D=null;if(v==="candles")CD=null;if(v==="txns"||v==="bots")TV=null;if(v==="signal")RP=null}}
 busy=false;lastLoad=Date.now();if(my===sess&&view===v)render()}
function selectCoin(k){cur=k||null;D=TV=CD=RP=null;errMsg="";if(cur){loadFor(view,false)}render()}
function openCoin(k){cur=k;D=TV=CD=RP=null;view="details";drawn="";loadFor("details",false);render()}
function render(){if(!ST)return;$("#conn").className="pill b-"+ST.conn;$("#conn").textContent=ST.conn;$("#conn").title=(ST.cycle.errors||[]).join(" | ");
 $("#banner").innerHTML=ST.warn.map(w=>'<div class="banner">'+esc(w)+"</div>").join("")+(ST.conn==="offline"?'<div class="banner">No market data is arriving: '+esc((ST.cycle.errors||["check your connection"]).join(" | "))+". Showing last known data.</div>":"");
 for(const b of document.querySelectorAll("#nav button"))b.classList.toggle("on",b.dataset.v===view);
 try{if(view==="settings"){if(!SET_DRAWN||drawn!=="settings"){$("#view").innerHTML=settingsHTML();SET_DRAWN=true;drawn="settings"}const p=$("#provbox");if(p)p.innerHTML=provHTML();return}
  if(drawn!==view){$("#view").innerHTML=skel(view);drawn=view;SET_DRAWN=false;if(view==="coins"){$("#fl").value=Fl.minliq;$("#fr").value=Fl.maxrisk;$("#fw").checked=Fl.watch;$("#sq").value=searchQ}}
  const cs=$("#csel");if(cs){const sig=ST.coins.map(c=>c.key).join(",")+"|"+cur;if(cs.dataset.sig!==sig){cs.dataset.sig=sig;cs.innerHTML='<option value="">Choose a coin…</option>'+(cur&&!ST.coins.find(c=>c.key===cur)?'<option value="'+esc(cur)+'">'+esc(cur.split(":")[1].slice(0,8))+"</option>":"")+ST.coins.map(c=>'<option value="'+esc(c.key)+'">'+esc(c.sym)+" ("+esc(c.chain)+")</option>").join("");cs.value=cur||""}}
  BODY[view]()}catch(e){$("#view").innerHTML='<div class="card dn">Display error: '+esc(e.message)+"</div>";drawn=""}}
function go(v){view=v;drawn="";searchRes=v==="coins"?searchRes:null;loadFor(v,false);render();window.scrollTo(0,0)}
let polling=false;async function poll(force){if(polling&&!force)return;polling=true;try{const s=await api("/api/state?since="+(force?-1:ver));if(!s.unchanged){ST=s;ver=s.ver;const ae=document.activeElement;if(!(ae&&/^(INPUT|SELECT|TEXTAREA)$/.test(ae.tagName||"")&&view!=="settings"))render();if(SCOPED.includes(view)&&cur&&Date.now()-lastLoad>15000&&!busy)loadFor(view,false);else if(view==="txns"&&feedMode&&Date.now()-lastLoad>15000)loadFor("txns",false)}}catch(e){$("#conn").className="pill b-offline";$("#conn").textContent="disconnected";$("#conn").title=e.message}finally{polling=false}}

/* ---------- events ---------- */
document.addEventListener("click",async e=>{const t=e.target;
 const nb=t.closest("#nav button");if(nb)return go(nb.dataset.v);
 const g=t.closest("[data-go]");if(g){e.preventDefault();return go(g.dataset.go)}
 const ag=t.closest("[data-agent]");if(ag){agSel=ag.dataset.agent;return render()}
 const tx=t.closest("[data-tx]");if(tx){e.preventDefault();const u=EX_TX[tx.dataset.chain];if(u)window.open(u.replace("%s",tx.dataset.tx),"_blank","noopener,noreferrer");return}
 const a=t.closest("[data-act]");if(a){e.stopPropagation();const k=a.dataset.k;if(a.dataset.act==="watch"){const on=!((ST.coins.find(x=>x.key===k)||{}).watch||(D&&D.coin.key===k&&D.watch));await act(()=>post("/api/watch",{key:k,on}));if(D&&D.coin.key===k)D.watch=on;return render()}}
 const gw_=t.closest("[data-gw]");if(gw_){gw=gw_.dataset.gw;return render()}
 const so=t.closest("[data-sort]");if(so){const c=so.dataset.sort;Fl.dir=Fl.sortc===c?-Fl.dir:(c==="sym"?1:-1);Fl.sortc=c;return render()}
 const tfb=t.closest("[data-tf]");if(tfb){tf=tfb.dataset.tf;CD=null;render();return loadFor("candles",false)}
 const fm=t.closest("[data-fm]");if(fm){feedMode=fm.dataset.fm==="1";return loadFor("txns",false).then(render)}
 const aw=t.closest("[data-addw]");if(aw)return act(()=>post("/api/wallet/add",{address:aw.dataset.addw,chain:aw.dataset.chain,label:"from bot analysis"}));
 const ow=t.closest("[data-openw]");if(ow){return openWallet(ow.dataset.openw,ow.dataset.chain)}
 const rw=t.closest("[data-rmw]");if(rw)return act(()=>post("/api/wallet/remove",{address:rw.dataset.rmw}));
 const row=t.closest("[data-k]");if(row&&!t.closest("button,a,input,select"))return openCoin(row.dataset.k);
 switch(t.id){
  case"rf":await act(()=>post("/api/refresh"),"Refreshing…");return loadFor(view,true);
  case"cref":return loadFor(view,true);
  case"sclr":searchRes=null;searchQ="";const q=$("#sq");if(q)q.value="";return render();
  case"fetchtx":t.disabled=true;await loadFor(view,true);return;
  case"holders":t.disabled=true;await act(()=>post("/api/holders",{key:cur}),"Holder data loaded");return loadFor(view,false);
  case"aimkt":try{t.disabled=true;await post("/api/ai/market");toast("AI market analysis received")}catch(er){toast(er.message,true)}return poll(true);
  case"aigo":try{t.disabled=true;t.textContent="Running…";await post("/api/ai/coin",{key:cur});toast("AI analysis received")}catch(er){toast(er.message,true)}await poll(true);return loadFor(view,false);
  case"ssave":case"ksave":{const n=id=>$("#s_"+id).value,s={};for(const k of["refresh_s","max_tracked","min_liq_discovery","min_liq","min_age_h","whale_usd","whale_liq_pct","ai_max_age_min","trades_per_cycle","gt_rpm"])s[k]=n(k);
   s.discovery=$("#s_discovery").checked;s.chains=n("chains").split(",").map(x=>x.trim().toLowerCase()).filter(Boolean);s.ai_provider=n("ai_provider");s.ai_model=n("ai_model").trim();s.ai_base=n("ai_base").trim();
   const r=await act(()=>post("/api/settings",s),"Settings saved");if(r&&t.id==="ksave"&&$("#k_ai").value.trim()){await act(()=>post("/api/secrets",{name:"ai_key",value:$("#k_ai").value}),"AI key saved");$("#k_ai").value=""}if(r){drawn="";render()}return}
  case"kclear":await act(()=>post("/api/secrets",{name:"ai_key",value:""}),"AI key removed");drawn="";return render();
  case"cgsave":{const v=$("#k_cg").value.trim();if(!v)return toast("Paste a key first",true);await act(()=>post("/api/secrets",{name:"cg_key",value:v}),"CoinGecko key saved");drawn="";return render()}
  case"cgclear":await act(()=>post("/api/secrets",{name:"cg_key",value:""}),"CoinGecko key removed");drawn="";return render();
  case"rsave":{const v=$("#k_rpc").value.trim();if(!v)return toast("Paste an https RPC URL first",true);await act(()=>post("/api/secrets",{name:"sol_rpc",value:v}),"RPC URL saved");drawn="";return render()}
  case"rclear":await act(()=>post("/api/secrets",{name:"sol_rpc",value:""}),"Using the public RPC");drawn="";return render();
  case"stop":if(confirm("Stop the Meme Desk server?")){try{await post("/api/shutdown");$("#view").innerHTML='<div class="card">Server stopped. Run the script again to restart.</div>';$("#conn").textContent="stopped";clearInterval(pollTimer)}catch(er){toast(er.message,true)}}return}});
const EX_TX={solana:"https://solscan.io/tx/%s",ethereum:"https://etherscan.io/tx/%s",base:"https://basescan.org/tx/%s",bsc:"https://bscscan.com/tx/%s",arbitrum:"https://arbiscan.io/tx/%s",polygon:"https://polygonscan.com/tx/%s",avalanche:"https://snowtrace.io/tx/%s",optimism:"https://optimistic.etherscan.io/tx/%s"};
async function openWallet(addr,chain){view="wallets";drawn="";render();try{WP=await api("/api/wallet?address="+encodeURIComponent(addr)+"&chain="+encodeURIComponent(chain)+"&rpc="+(chain==="solana"?"1":"0"));render()}catch(e){toast(e.message,true)}}
document.addEventListener("keydown",e=>{if((e.key==="Enter"||e.key===" ")&&e.target.dataset&&(e.target.dataset.k||e.target.dataset.agent)&&!/INPUT|SELECT|BUTTON/.test(e.target.tagName||"")){e.preventDefault();if(e.target.dataset.agent){agSel=e.target.dataset.agent;render()}else openCoin(e.target.dataset.k)}});
document.addEventListener("submit",async e=>{e.preventDefault();const id=e.target.id;
 if(id==="sf"){const q=$("#sq").value.trim();if(q.length<2)return toast("Type at least 2 characters",true);searchQ=q;$("#vbody").innerHTML='<span class="spin"></span> Searching…';try{const r=await api("/api/search?q="+encodeURIComponent(q));searchRes=r.results;if(!r.results.length)toast("No tokens found for “"+q+"”")}catch(er){toast(er.message,true)}render()}
 if(id==="wadd"){const a=$("#wa2").value.trim();if(!a)return toast("Enter an address",true);const r=await act(()=>post("/api/wallet/add",{address:a,chain:$("#wc2").value,label:$("#wl2").value}));if(r){$("#wa2").value="";$("#wl2").value=""}}
 if(id==="wf"){const a=$("#wa").value.trim();if(!a)return toast("Enter an address",true);openWallet(a,$("#wc").value)}});
document.addEventListener("change",async e=>{const t=e.target;
 if(t.id==="csel")return selectCoin(t.value);
 if(t.id==="fc"){Fl.chain=t.value;render()}else if(t.id==="fl"){Fl.minliq=+t.value;render()}else if(t.id==="fr"){Fl.maxrisk=+t.value;render()}else if(t.id==="fw"){Fl.watch=t.checked;render()}
 else if(t.id==="sidef"){sideF=t.value;render()}else if(t.id==="minf"){minF=+t.value;render()}
 else if(t.dataset&&t.dataset.ind){IND[t.dataset.ind]=t.checked;render()}});
const pollTimer=setInterval(()=>poll(false),4000);poll(true);
</script></body></html>
"""


# ----------------------------------------------------------------------------- polling
def ingest(coins, mon):
    with LOCK:
        for key, c in coins.items():
            old = S["coins"].get(key)
            c["mon"], c["src"] = mon, (old or {}).get("src", [])
            S["coins"][key] = c
            h = S["hist"].setdefault(key, deque(maxlen=400))
            if not h or c["updated"] - h[-1][0] > 5:
                h.append([c["updated"], c["price"], c["liq"], c["vol"].get("h24")])
            c["analysis"] = analyse(c)


def reanalyse(key):
    with LOCK:
        c = S["coins"].get(key)
        if c:
            c["analysis"] = analyse(c)
            scan_alerts(c)


def focus_keys():
    now = time.time()
    with LOCK:
        for k in [k for k, t in S["focus"].items() if now - t > 600]:
            S["focus"].pop(k)
        return sorted(S["focus"], key=lambda k: -S["focus"][k])


def deep_fetch(max_trades, max_candles):
    """Per-cycle budget of extra provider calls (trades and 15m candles): the viewed coin first, then the watchlist."""
    with LOCK:
        order = [k for k in focus_keys() if k in S["coins"]] + [k for k in S["watch"] if k in S["coins"] and k not in S["focus"]]
        coins = {k: S["coins"][k] for k in order}
        lt = {k: S["trades"].get(k, {}).get("fetched", 0) for k in order}
        lc = {k: (S["candles"].get((k, "15m")) or (0,))[0] for k in order}
    errs = []
    for k in sorted(order, key=lambda k: lt[k])[:max_trades]:
        if time.time() - lt[k] < 25:
            continue
        try:
            ingest_trades(coins[k], get_trades(coins[k]))
            reanalyse(k)
        except ApiError as e:
            errs.append(str(e))
            if "rate limit" in str(e):
                break
    for k in sorted(order, key=lambda k: lc[k])[:max_candles]:
        if time.time() - lc[k] < 240:
            continue
        try:
            get_candles(coins[k], "15m", max_age=0)
            reanalyse(k)
        except ApiError as e:
            errs.append(str(e))
            if "rate limit" in str(e):
                break
    return errs


def poll_cycle():
    t0 = time.time()
    with LOCK:
        st, errs = dict(S["settings"]), []
        S["cycle"]["start"] = t0
        for n in ("trend", "volume", "liquidity", "risk", "bot", "whale", "consensus"):
            a = S["agents"].setdefault(n, {"runs": 0, "errors": 0, "last_run": 0, "last_ms": 0, "last_error": None, "status": "idle", "cerr": 0})
            a["status"], a["cerr"] = "running", 0
        wanted = OrderedDict()
        for k in focus_keys():
            wanted[k] = "viewing"
        for k in S["watch"]:
            wanted.setdefault(k, "watchlist")
        protected = set(wanted)
        ncy = S["cycle"]["n"]
    bump()
    labels, lists = ("boost-top", "boost-new", "profile"), {}
    if st["discovery"]:
        for kind, label in zip(("top", "latest", "profiles"), labels):
            try:
                lists[label] = ds_list(kind)
            except ApiError as e:
                errs.append(str(e))
        if ncy % 3 == 0:
            try:
                pools = gt_new_solana_pools()
                with LOCK:
                    for p in pools:
                        if "pump" in p["dex"].lower() or p["addr"].endswith("pump"):
                            S["launch"]["solana:" + p["addr"]] = p
                    if len(S["launch"]) > 60:
                        for k in sorted(S["launch"], key=lambda k: S["launch"][k].get("created") or 0)[:len(S["launch"]) - 60]:
                            S["launch"].pop(k)
            except ApiError as e:
                errs.append(str(e))
        with LOCK:
            lists["launch"] = [("solana", k.split(":", 1)[1]) for k in sorted(S["launch"], key=lambda k: -(S["launch"][k].get("created") or 0))[:15]]
    idx, chains = {l: 0 for l in labels + ("launch",)}, set(st["chains"])
    while len(wanted) < st["max_tracked"]:
        moved = False
        for l in labels + ("launch",):
            arr = lists.get(l, [])
            while idx[l] < len(arr):
                ch, ad = arr[idx[l]]
                idx[l] += 1
                if chains and ch not in chains and l != "launch":
                    continue
                if ch + ":" + ad not in wanted:
                    wanted[ch + ":" + ad] = l
                    moved = True
                    break
        if not moved:
            break
    by = defaultdict(list)
    for k in wanted:
        ch, ad = k.split(":", 1)
        by[ch].append(ad)
    found = {}
    for ch, ads in by.items():
        for i in range(0, len(ads), 30):
            chunk = ads[i:i + 30]
            try:
                found.update(best_pairs(ds_tokens(ch, chunk), {a.lower() for a in chunk}))
            except ApiError as e:
                errs.append(str(e))
            if STOP.is_set():
                return
    found = {k: c for k, c in found.items() if k in protected or wanted.get(k) == "launch" or (c["liq"] or 0) >= st["min_liq_discovery"]}
    ingest(found, True)
    errs += deep_fetch(st["trades_per_cycle"], 1)
    with LOCK:
        for k, c in S["coins"].items():
            c["mon"] = k in found
            if k in found:
                c["src"] = [wanted.get(k, "")] + (["watchlist"] if k in S["watch"] else [])
        for k in [k for k, c in S["coins"].items() if time.time() - c["updated"] > 1800 and k not in S["watch"] and k not in S["focus"]]:
            S["coins"].pop(k, None)
            S["hist"].pop(k, None)
        for c in found.values():
            scan_alerts(c)
        compute_overview()
        for n in ("trend", "volume", "liquidity", "risk", "bot", "whale", "consensus"):
            a = S["agents"][n]
            a["status"] = "error" if a["cerr"] else "idle"
        cy = S["cycle"]
        cy.update(n=cy["n"] + 1, end=time.time(), ms=int((time.time() - t0) * 1000), errors=errs[:6], found=len(found))
    try:
        save_state()
    except OSError as e:
        warn("Could not save state: %s" % e)
    bump()


_poller = None
_poller_lock = threading.Lock()


def poller():
    while not STOP.is_set():
        t0 = time.time()
        try:
            poll_cycle()
        except Exception as e:
            with LOCK:
                S["cycle"]["errors"] = ["internal: %s" % type(e).__name__]
            log("Data cycle failed: %s" % scrub(e), "dn")
            bump()
        WAKE.wait(max(1.0, S["settings"]["refresh_s"] - (time.time() - t0)))
        WAKE.clear()


def start_poller():
    global _poller
    with _poller_lock:
        if _poller and _poller.is_alive():
            return
        _poller = threading.Thread(target=poller, name="poller", daemon=True)
        _poller.start()


def fetch_coin(key, force=False):
    if not KEY_RE.match(key):
        raise ApiError("Invalid coin key", True)
    with LOCK:
        if not force and key in S["coins"]:
            return S["coins"][key]
        if time.time() - S["last_fetch"].get(key, 0) < 8 and key in S["coins"]:
            return S["coins"][key]
        S["last_fetch"][key] = time.time()
    ch, ad = key.split(":", 1)
    found = best_pairs(ds_tokens(ch, [ad]), {ad.lower()})
    if key not in found:
        raise ApiError("DexScreener returned no pair for this token", True)
    with LOCK:
        mon = bool(S["coins"].get(key, {}).get("mon"))
    ingest(found, mon)
    bump()
    return S["coins"][key]


# ----------------------------------------------------------------------------- API views
def brief(c):
    a = c.get("analysis") or {}
    cs, vol = a.get("consensus") or {}, a.get("volume") or {}
    p = pump_info(c)
    return {"key": c["key"], "sym": c["sym"], "name": c["name"], "chain": c["chain"], "price": c["price"], "chg": c["chg"], "liq": c["liq"], "vol24": c["vol"].get("h24"), "age_h": age_h(c),
            "risk": (a.get("risk") or {}).get("risk"), "concl": cs.get("conclusion"), "sig": {k: (a.get(k) or {}).get("signal") for k in ("trend", "volume", "liquidity", "bot", "whale", "risk")},
            "uvol": vol.get("unusual"), "ratio": vol.get("ratio"), "watch": c["key"] in S["watch"], "mon": bool(c.get("mon")), "updated": c["updated"], "stale": is_stale(c), "logo": c.get("logo"),
            "pump": p["status"] if p else None, "dex": c.get("dex"), "has_tx": c["key"] in S["trades"], "tx1h": sum(x for x in ((c["tx"].get("h1") or {}).get("buys"), (c["tx"].get("h1") or {}).get("sells")) if x is not None)}


AGENT_DEFS = [
    ("trend", "Trend Analyst", "Deterministic Python: price-change windows, momentum, and indicators calculated from candles when fetched. Not AI."),
    ("volume", "Volume Analyst", "Deterministic Python: volume vs 24h baseline, buy/sell pressure, spike detection. Not AI."),
    ("liquidity", "Liquidity & Exit-Risk Analyst", "Deterministic Python: liquidity depth, estimated exit impact, locally collected liquidity change. Not AI."),
    ("bot", "Bot Pattern Analyst", "Deterministic Python heuristics on observed trades. Findings are 'suspected', never proof."),
    ("whale", "Whale & Wallet Analyst", "Deterministic Python: large trades, net flow, concentration, tracked wallets from observed trades."),
    ("risk", "Risk & Rug-Pull Analyst", "Deterministic Python checklist. Contract-level checks are NOT connected (listed as missing)."),
    ("ai", "AI Research Analyst", "Real LLM API call (on demand) to your configured provider."),
    ("consensus", "Consensus Analyst", "Deterministic Python rules combining agents, listing agreements and conflicts. Not AI.")]


def agents_state():
    out = []
    for aid, name, impl in AGENT_DEFS:
        a = dict(S["agents"].get(aid) or {"runs": 0, "errors": 0, "last_run": 0, "last_ms": 0, "last_error": None, "status": "idle"})
        if aid == "ai":
            a["status"] = "running" if S["ai"]["busy"] else "not_configured" if not ai_configured() else "error" if S["ai"]["error"] else "idle"
            impl = ("Real LLM call via %s / %s (on demand)" % (S["settings"]["ai_provider"], S["settings"]["ai_model"])) if ai_configured() else "Real LLM call: AI API NOT CONFIGURED (add a key in Settings)"
        a.pop("cerr", None)
        a.update(id=aid, name=name, impl=impl)
        out.append(a)
    return out


def capabilities():
    k = lambda n: bool(secret(n))
    return [
        {"id": "dexscreener", "name": "DexScreener public API", "provides": "Token/pair prices, price change, liquidity, volume, transaction counts, FDV/market cap, pair age, logos, discovery lists", "key": "none", "tier": "Free; documented limits about 60/min (discovery lists) and 300/min (pairs, search)", "status": P_DS.status, "doc": "https://docs.dexscreener.com/api/reference"},
        {"id": "geckoterminal", "name": "GeckoTerminal / CoinGecko on-chain API", "provides": "Individual trades with wallet addresses, OHLCV candles, new pools", "key": "optional (CoinGecko demo key)" + (" - set" if k("cg_key") else " - not set"), "tier": "Keyless public access is rate limited (the app defaults to 10 calls/min); a free CoinGecko demo key raises limits; check current plan limits", "status": P_GT.status, "doc": "https://docs.coingecko.com/reference/pool-trades-contract-address"},
        {"id": "solana_rpc", "name": "Solana JSON-RPC", "provides": "Token holder concentration (largest accounts), wallet signatures and balance (Solana only)", "key": "optional custom RPC URL" + (" - set" if k("sol_rpc") else " - using public RPC"), "tier": "Public RPC is free but heavily rate limited; providers such as Helius offer a free tier with an API key (check their current limits)", "status": P_RPC.status, "doc": "https://solana.com/docs/rpc"},
        {"id": "llm", "name": "LLM API (Anthropic or OpenAI-compatible)", "provides": "AI Research Analyst reports", "key": "required" + (" - set" if ai_configured() else " - NOT CONFIGURED"), "tier": "Paid per use by your provider", "status": P_AI.status if ai_configured() else "not_configured", "doc": "https://docs.claude.com"},
        {"id": "pumpfun", "name": "Pump.fun official data API", "provides": "Bonding-curve progress, creator, graduation events", "key": "n/a", "tier": "Pump.fun publishes no official public data API. Third-party options (Solana Tracker, Codex, Bitquery; PumpPortal is unofficial) need keys or are paid. Moralis's Pump.fun REST endpoints were sunset on 31 July 2026.", "status": "unavailable", "doc": "https://docs.bitquery.io/docs/blockchain/Solana/Pumpfun/"},
        {"id": "contract", "name": "Contract-safety provider", "provides": "Honeypot/sell-tax simulation, mint/freeze authority, LP lock, creator history", "key": "not connected", "tier": "Not integrated: the Risk Analyst lists these as unchecked", "status": "unavailable", "doc": ""}]


def state_summary():
    with LOCK:
        cy, cs = S["cycle"], sorted(S["coins"].values(), key=lambda c: -(c["vol"].get("h24") or 0))
        keep = [c for c in cs if c.get("mon") or c["key"] in S["watch"] or c["key"] in S["focus"] or pump_info(c)][:160]
        conn = "starting" if not cy["n"] else "online" if cy["found"] and not cy["errors"] else "degraded" if cy["found"] else "offline"
        return {"ver": S["ver"], "now": time.time(), "version": VERSION, "conn": conn, "cycle": dict(cy), "warn": list(S["warn"]), "coins": [brief(c) for c in keep], "watch": list(S["watch"]),
                "wallets": list(S["wallets"]), "overview": S["overview"], "agents": agents_state(), "alerts": S["alerts"][:40], "settings": dict(S["settings"]), "feed": S["feed"][:50],
                "providers": [p.snap() for p in PROVS], "caps": capabilities(), "gt_chains": sorted(GT_NET),
                "secrets": dict({n: bool(secret(n)) for n in ENVN}, ai_key_env=bool(os.environ.get("DESK_AI_KEY")), sol_rpc_host=urllib.parse.urlparse(secret("sol_rpc") or DEFAULT_SOL_RPC).hostname),
                "ai": {"configured": ai_configured(), "provider": S["settings"]["ai_provider"], "model": S["settings"]["ai_model"], "busy": S["ai"]["busy"], "error": S["ai"]["error"], "history": S["ai"]["history"]}}


def coin_detail(key):
    with LOCK:
        c = S["coins"].get(key)
        if not c:
            raise ApiError("Unknown coin", True)
        cd = {k: c[k] for k in ("key", "sym", "name", "chain", "addr", "price", "chg", "vol", "tx", "liq", "fdv", "mcap", "created", "dex", "pair", "url", "logo", "links", "boosts", "quote", "updated", "mon")}
        cd.update(age_h=age_h(c), stale=is_stale(c), pump=pump_info(c))
        miss = []
        if c["mcap"] is None:
            miss.append("Market cap is not provided by DexScreener for this pair. FDV (fully diluted valuation) is shown separately and is NOT market cap.")
        for n, v in (("FDV", c["fdv"]), ("Liquidity", c["liq"]), ("Pair creation time", c["created"])):
            if v is None:
                miss.append(n + " not provided.")
        for w in W:
            if c["chg"].get(w) is None:
                miss.append("Price change %s unavailable." % w)
        wr = []
        if is_stale(c):
            wr.append("Data is stale: last updated %ds ago%s." % (time.time() - c["updated"], "" if c.get("mon") else " (not in the auto-refresh set: press Refresh)"))
        wr.append("Prices come from the deepest-liquidity pool DexScreener lists for this token; other pools may differ.")
        wr.append("Public market data cannot show every participant or any wallet's identity.")
        return {"coin": cd, "analysis": c["analysis"], "session": [[p[0], p[1], p[2]] for p in list(S["hist"].get(key, []))[-300:]], "onchain": S["onchain"].get(key), "ai": S["ai"]["coins"].get(key),
                "explorer": explorer(c["chain"], "token", c["addr"]), "watch": key in S["watch"], "missing": miss, "warnings": wr, "tx_ok": c["chain"] in GT_NET and bool(c.get("pair")),
                "trades_fetched": S["trades"].get(key, {}).get("fetched"), "source": "DexScreener public API", "ai_configured": ai_configured(), "now": time.time()}


def trades_view(key, fetch):
    with LOCK:
        c = S["coins"].get(key)
        if not c:
            raise ApiError("Unknown coin", True)
        S["focus"][key] = time.time()
    err = None
    if fetch:
        try:
            ingest_trades(c, get_trades(c))
            reanalyse(key)
            bump()
        except ApiError as e:
            err = str(e)
            with LOCK:
                S["trades"].setdefault(key, {"rows": OrderedDict(), "fetched": 0, "error": None})["error"] = err
    with LOCK:
        rows, tr = trade_list(key), analyse_trades(c, trade_list(key))
        tset = tracked_set(c["chain"])
        out = [dict(r, link=explorer(c["chain"], "tx", r["tx"]), wlink=explorer(c["chain"], "wallet", r["wallet"]), tracked=(r["wallet"] if c["chain"] == "solana" else r["wallet"].lower()) in tset) for r in rows[:200]]
        if tr:
            for lst in (tr["large"], tr["tracked"]):
                for r in lst:
                    r["link"], r["wlink"] = explorer(c["chain"], "tx", r["tx"]), explorer(c["chain"], "wallet", r["wallet"])
            for x in tr["top_wallets"] + tr["suspected"]:
                x["wlink"] = explorer(c["chain"], "wallet", x["wallet"])
        t = S["trades"].get(key, {})
        return {"key": key, "sym": c["sym"], "chain": c["chain"], "rows": out, "analysis": tr, "fetched": t.get("fetched"), "error": err or t.get("error"), "tx_ok": c["chain"] in GT_NET and bool(c.get("pair")),
                "bot": c["analysis"]["bot"], "whale": c["analysis"]["whale"], "source": "GeckoTerminal pool trades (documented endpoint; at most the last 300 trades in 24h)"}


def feed_view():
    with LOCK:
        rows = []
        for k, t in S["trades"].items():
            co = S["coins"].get(k)
            if not co:
                continue
            tset = tracked_set(co["chain"])
            for r in t["rows"].values():
                rows.append(dict(r, key=k, sym=co["sym"], chain=co["chain"], link=explorer(co["chain"], "tx", r["tx"]), tracked=(r["wallet"] if co["chain"] == "solana" else r["wallet"].lower()) in tset))
        rows.sort(key=lambda r: -r["t"])
        sus = []
        for k in S["trades"]:
            co = S["coins"].get(k)
            if co and co["analysis"]["bot"]["signal"] == "bearish":
                sus.append({"key": k, "sym": co["sym"], "chain": co["chain"], "summary": co["analysis"]["bot"]["summary"]})
        return {"rows": rows[:200], "coins_with_trades": len(S["trades"]), "suspected_coins": sus}


def candles_view(key, tf):
    with LOCK:
        c = S["coins"].get(key)
        if not c:
            raise ApiError("Unknown coin", True)
        S["focus"][key] = time.time()
        sess = [[p[0], p[1]] for p in S["hist"].get(key, [])]
        cc = dict(c)
    try:
        rows = get_candles(cc, tf)
    except ApiError as e:
        return {"ok": False, "error": str(e), "tf": tf, "session": sess, "source": "Locally collected snapshots (this app, since startup). Candlesticks need provider OHLCV, which is unavailable here."}
    ta = tech_analysis(rows)
    reanalyse(key)
    bump()
    out = {"ok": True, "tf": tf, "candles": rows, "source": "GeckoTerminal OHLCV (source-provided)", "fetched": time.time(), "n": len(rows), "tech": None}
    if ta:
        out["tech"] = {k: ta[k] for k in ("ema20", "sma50", "rsi14", "macd", "macd_signal", "macd_hist", "signals", "support", "resistance", "vol_x", "note")}
    else:
        out["note"] = "Fewer than 20 candles: indicators were not calculated."
    return out


# ----------------------------------------------------------------------------- HTTP server
class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class Handler(BaseHTTPRequestHandler):
    server_version = "MemeDesk/" + VERSION

    def log_message(self, *a):
        pass

    def send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(clean(body), separators=(",", ":"))
        b = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data: https://cdn.dexscreener.com; connect-src 'self'; frame-ancestors 'none'")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def host_ok(self):
        if HOST not in ("127.0.0.1", "localhost", "::1"):
            return True
        return (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]").lower() in ("127.0.0.1", "localhost", "::1")

    def guard(self, fn):
        try:
            path = urllib.parse.urlparse(self.path).path
            if path == "/healthz" and self.command == "GET":
                return self.send(200, {"ok": True, "service": "meme-desk-live"})
            if HOST not in ("127.0.0.1", "localhost", "::1"):
                auth = self.headers.get("Authorization", "")
                valid = False
                if auth.startswith("Basic "):
                    try:
                        raw = base64.b64decode(auth[6:], validate=True).decode("utf-8")
                        user, password = raw.split(":", 1)
                        valid = hmac.compare_digest(user, PUBLIC_AUTH_USER) and hmac.compare_digest(password, PUBLIC_AUTH_PASSWORD)
                    except Exception:
                        valid = False
                if not valid:
                    return self.send(401, {"error": "Authentication required"}, extra={"WWW-Authenticate": 'Basic realm="Meme Desk Live", charset="UTF-8"'})
            if not self.host_ok():
                return self.send(403, {"error": "Forbidden host"})
            fn()
        except ApiError as e:
            self.send(502 if not e.fatal else 400, {"error": scrub(e)})
        except ValueError as e:
            self.send(400, {"error": scrub(e)})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            print("Handler error:", type(e).__name__, scrub(e))
            try:
                self.send(500, {"error": "Internal error (%s)" % type(e).__name__})
            except Exception:
                pass

    def do_GET(self):
        self.guard(self._get)

    def do_POST(self):
        self.guard(self._post)

    def _get(self):
        u = urllib.parse.urlparse(self.path)
        q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
        key = q.get("key", "")

        def need_key():
            if not KEY_RE.match(key):
                raise ValueError("Invalid coin key")
        if u.path == "/":
            return self.send(200, PAGE.replace("__TOKEN__", TOKEN), "text/html; charset=utf-8")
        if u.path == "/api/state":
            if q.get("since") == str(S["ver"]):
                return self.send(200, {"unchanged": True, "ver": S["ver"]})
            return self.send(200, state_summary())
        if u.path == "/api/coin":
            need_key()
            if q.get("refresh") == "1" or key not in S["coins"]:
                fetch_coin(key, force=True)
            with LOCK:
                S["focus"][key] = time.time()
            return self.send(200, coin_detail(key))
        if u.path == "/api/candles":
            need_key()
            if key not in S["coins"]:
                fetch_coin(key)
            return self.send(200, candles_view(key, q.get("tf", "15m")))
        if u.path == "/api/trades":
            need_key()
            if key not in S["coins"]:
                fetch_coin(key)
            return self.send(200, trades_view(key, q.get("fetch") == "1"))
        if u.path == "/api/feed":
            return self.send(200, feed_view())
        if u.path == "/api/report":
            need_key()
            if key not in S["coins"]:
                fetch_coin(key)
            return self.send(200, make_report(S["coins"][key]))
        if u.path == "/api/wallet":
            ch = q.get("chain", "solana")
            if ch not in EXPL and ch != "solana":
                raise ValueError("Unsupported chain")
            return self.send(200, wallet_profile(q.get("address", "").strip(), ch, q.get("rpc") == "1"))
        if u.path == "/api/search":
            term = q.get("q", "").strip()
            if not (2 <= len(term) <= 60):
                raise ValueError("Search text must be 2 to 60 characters")
            top = sorted(best_pairs(ds_search(term)).values(), key=lambda c: -(c["liq"] or 0))[:25]
            ingest({c["key"]: c for c in top if c["key"] not in S["coins"] or not S["coins"][c["key"]].get("mon")}, False)
            with LOCK:
                return self.send(200, {"results": [brief(S["coins"][c["key"]]) for c in top if c["key"] in S["coins"]], "query": term})
        self.send(404, {"error": "Not found"})

    def _post(self):
        if not hmac.compare_digest(self.headers.get("X-Desk-Token", ""), TOKEN):
            return self.send(403, {"error": "Missing or wrong session token. Reload the page."})
        n = int(self.headers.get("Content-Length") or 0)
        if n > 65536:
            return self.send(413, {"error": "Request too large"})
        try:
            d = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            raise ValueError("Request body was not valid JSON")
        if not isinstance(d, dict):
            raise ValueError("Request body must be a JSON object")
        p, key = self.path, d.get("key", "")
        ok = lambda msg="", **kw: self.send(200, dict(ok=True, msg=msg, **kw))
        if p == "/api/settings":
            with LOCK:
                S["settings"] = clean_settings(d, S["settings"])
            save_config()
            WAKE.set()
            bump()
            return ok("Settings saved")
        if p == "/api/secrets":
            name, val = d.get("name"), d.get("value", "")
            if name not in ENVN or not isinstance(val, str):
                raise ValueError("Unknown secret")
            val = val.strip()
            if val:
                if name in ("ai_key", "cg_key") and (not 8 <= len(val) <= 300 or re.search(r"\s", val)):
                    raise ValueError("That does not look like an API key")
                if name == "sol_rpc" and (len(val) > 500 or not valid_https(val)):
                    raise ValueError("RPC URL must start with https://")
            with LOCK:
                if val:
                    S["secrets"][name] = val
                else:
                    S["secrets"].pop(name, None)
            save_secrets()
            bump()
            return ok("Saved" if val else "Cleared")
        if p == "/api/watch":
            if not KEY_RE.match(key):
                raise ValueError("Invalid coin key")
            with LOCK:
                if d.get("on"):
                    if key not in S["watch"]:
                        if len(S["watch"]) >= 50:
                            raise ValueError("Watchlist is limited to 50 coins")
                        S["watch"].append(key)
                elif key in S["watch"]:
                    S["watch"].remove(key)
            save_state()
            WAKE.set()
            bump()
            return ok("Watchlist updated")
        if p == "/api/wallet/add":
            addr, ch = str(d.get("address", "")).strip(), str(d.get("chain", "solana"))
            if not ADDR_RE.match(addr) or (ch not in EXPL):
                raise ValueError("Enter a valid wallet address and a supported chain")
            with LOCK:
                if any(w["addr"] == addr and w["chain"] == ch for w in S["wallets"]):
                    raise ValueError("Wallet is already tracked")
                if len(S["wallets"]) >= 50:
                    raise ValueError("Tracked wallets are limited to 50")
                S["wallets"].append({"addr": addr, "chain": ch, "label": str(d.get("label", ""))[:40]})
            save_state()
            bump()
            return ok("Wallet added")
        if p == "/api/wallet/remove":
            addr = str(d.get("address", ""))
            with LOCK:
                S["wallets"] = [w for w in S["wallets"] if w["addr"] != addr]
            save_state()
            bump()
            return ok("Wallet removed")
        if p == "/api/refresh":
            WAKE.set()
            return ok("Refresh requested")
        if p == "/api/ai/coin":
            if not KEY_RE.match(key):
                raise ValueError("Invalid coin key")
            return ok("", result=run_ai("coin", key))
        if p == "/api/ai/market":
            return ok("", result=run_ai("market"))
        if p == "/api/holders":
            if not KEY_RE.match(key) or not key.startswith("solana:"):
                raise ValueError("Holder check supports Solana tokens only")
            data = solana_holders(key.split(":", 1)[1])
            with LOCK:
                S["onchain"][key] = data
            reanalyse(key)
            bump()
            return ok("", holders=data)
        if p == "/api/shutdown":
            ok("Shutting down")
            threading.Thread(target=request_shutdown, daemon=True).start()
            return
        self.send(404, {"error": "Not found"})


_server = None


def request_shutdown():
    STOP.set()
    WAKE.set()
    if _server:
        _server.shutdown()


def main():
    global _server
    if HOST not in ("127.0.0.1", "localhost", "::1"):
        if not PUBLIC_AUTH_USER or len(PUBLIC_AUTH_PASSWORD) < 12:
            print("SECURITY ERROR: public hosting requires DESK_USERNAME and DESK_PASSWORD (at least 12 characters).")
            return 2
        print("Public bind enabled with HTTP Basic Authentication.")
    load_config()
    save_config()
    load_state()
    try:
        _server = Server((HOST, PORT), Handler)
    except OSError as e:
        print("Cannot start: port %d is busy (%s). Another Meme Desk may be running. Stop it or set DESK_PORT." % (PORT, e))
        return 1
    for sg in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sg, lambda *_: threading.Thread(target=request_shutdown, daemon=True).start())
        except (ValueError, OSError):
            pass
    start_poller()
    print("Meme Desk Live %s running (research only: no trading of any kind).\nOpen http://127.0.0.1:%d in your browser.\nStop with Settings > Stop server, or the stop button in Pydroid." % (VERSION, PORT))
    try:
        _server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        STOP.set()
        WAKE.set()
        _server.server_close()
        if _poller:
            _poller.join(timeout=5)
        try:
            save_state()
        except OSError:
            pass
        print("Stopped. Watchlist and tracked wallets saved.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
