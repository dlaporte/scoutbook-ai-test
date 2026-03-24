import hashlib
import json
import logging
from time import monotonic

import httpx

logger = logging.getLogger("scoutbook.api")

API_BASE_URL = "https://api.scouting.org"
AUTH_BASE_URL = "https://auth.scouting.org"

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# ── Shared HTTP client (connection pooling + keep-alive) ──

_http = httpx.AsyncClient(timeout=30.0)

# ── Response cache ──

_cache: dict[str, tuple[float, object]] = {}
_cache_writes = 0
_CACHE_MAX_ENTRIES = 1024


def _cache_key(
    endpoint: str, method: str, token: str | None,
    params: dict | None, body: dict | list | None,
) -> str:
    raw = json.dumps(
        [endpoint, method, token, sorted((params or {}).items()), body],
        sort_keys=True, default=str,
    )
    return hashlib.sha256(raw.encode()).hexdigest()


def _cache_prune() -> None:
    """Remove expired entries; if still over cap, evict oldest by expiry."""
    now = monotonic()
    expired = [k for k, (exp, _) in _cache.items() if exp <= now]
    for k in expired:
        del _cache[k]
    if len(_cache) > _CACHE_MAX_ENTRIES:
        by_expiry = sorted(_cache.items(), key=lambda kv: kv[1][0])
        to_evict = len(_cache) - _CACHE_MAX_ENTRIES
        for k, _ in by_expiry[:to_evict]:
            del _cache[k]


async def api_request(
    endpoint: str,
    token: str | None = None,
    method: str = "GET",
    body: dict | list | None = None,
    params: dict[str, str | None] | None = None,
    cache_ttl: float | None = None,
) -> dict | list:
    """Make an authenticated request to api.scouting.org."""
    global _cache_writes

    # Filter out None/empty params
    filtered_params = {}
    if params:
        for k, v in params.items():
            if v is not None and v != "":
                filtered_params[k] = v

    # Check cache
    if cache_ttl is not None:
        key = _cache_key(endpoint, method, token, filtered_params, body)
        entry = _cache.get(key)
        if entry and entry[0] > monotonic():
            logger.debug("Cache HIT: %s", endpoint)
            return entry[1]
        logger.debug("Cache MISS: %s", endpoint)

    method = method.upper()
    url = f"{API_BASE_URL}{endpoint}"

    headers = {
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None and method == "POST":
        headers["Content-Type"] = "application/json"
    logger.debug("API %s %s", method, endpoint)

    try:
        if method == "POST":
            resp = await _http.post(url, headers=headers, json=body, params=filtered_params or None)
        elif method == "GET":
            resp = await _http.get(url, headers=headers, params=filtered_params or None)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")
    except httpx.TimeoutException:
        raise RuntimeError(f"Request timed out: {method} {endpoint}")
    except httpx.ConnectError:
        raise RuntimeError(f"Unable to reach BSA API: {method} {endpoint}")

    if resp.status_code >= 400:
        try:
            err = resp.json()
            msg = err.get("message") or err.get("errorDesc") or resp.text
        except Exception:
            msg = resp.text
        logger.warning("API %s %s -> %d: %s", method, endpoint, resp.status_code, msg)
        raise RuntimeError(f"API error ({resp.status_code}): {msg}")

    logger.debug("API %s %s -> %d", method, endpoint, resp.status_code)
    result = resp.json()

    # Store in cache
    if cache_ttl is not None:
        _cache[key] = (monotonic() + cache_ttl, result)
        _cache_writes += 1
        if _cache_writes % 100 == 0 or len(_cache) > _CACHE_MAX_ENTRIES:
            _cache_prune()

    return result
