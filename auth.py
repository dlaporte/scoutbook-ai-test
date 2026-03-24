import asyncio
import logging
import time

import httpx
from api import API_BASE_URL, AUTH_BASE_URL, USER_AGENT, _http
from store import get_store, load_collection

logger = logging.getLogger("scoutbook.auth")

# Per-session auth: maps MCP access token string → BSA auth dict
_auth_sessions: dict[str, dict] = {}
_sessions_loaded = False
_sessions_lock = asyncio.Lock()


async def ensure_sessions_loaded():
    """Populate _auth_sessions from persistent store on first access."""
    global _sessions_loaded
    if _sessions_loaded:
        return

    async with _sessions_lock:
        # Double-check after acquiring lock
        if _sessions_loaded:
            return

        try:
            entries = await load_collection("sessions")
            now = int(time.time())
            restored = 0
            for key, val in entries:
                if val.get("expiryTime", 0) > now:
                    _auth_sessions[key] = val
                    restored += 1
            if restored:
                logger.info("Restored %d session(s) from persistent store", restored)
        except Exception:
            logger.warning("Failed to load sessions from persistent store", exc_info=True)
        finally:
            _sessions_loaded = True


async def login(username: str, password: str) -> dict:
    """Authenticate with BSA, fetch org GUID, return auth state dict."""
    logger.info("BSA login attempt for user=%s***", username[:2] if len(username) >= 2 else username)
    logger.debug("BSA login attempt for user=%s", username)
    login_url = f"{AUTH_BASE_URL}/api/users/{username}/authenticate"

    try:
        resp = await _http.post(
            login_url,
            headers={
                "User-Agent": USER_AGENT,
                "Content-Type": "application/json",
                "Accept": "application/json; version=2",
            },
            json={"password": password},
        )
    except httpx.TimeoutException:
        logger.warning("BSA login timed out for user=%s", username)
        raise RuntimeError("BSA login timed out. Please try again.")
    except httpx.ConnectError:
        logger.warning("Unable to reach BSA auth service for user=%s", username)
        raise RuntimeError("Unable to reach BSA authentication service.")

    if resp.status_code >= 400:
        logger.warning("BSA login failed for user=%s*** status=%d body=%s", username[:2] if len(username) >= 2 else username, resp.status_code, resp.text[:200])
        logger.debug("BSA login failed for user=%s status=%d body=%s", username, resp.status_code, resp.text[:200])
        if resp.status_code == 403:
            raise RuntimeError("LOGIN_FORBIDDEN")
        elif resp.status_code in (400, 401):
            raise RuntimeError("LOGIN_UNAUTHORIZED")
        else:
            raise RuntimeError(f"LOGIN_ERROR:{resp.status_code}")

    data = resp.json()
    token = data.get("token")
    person_guid = data.get("personGuid")
    user_id = data.get("account", {}).get("userId")

    if not token or not user_id or not person_guid:
        raise RuntimeError("Login response missing required fields (token, userId, or personGuid)")

    # Try to extract token expiry from response; fall back to 7 hours
    expires_in = data.get("expiresIn") or data.get("expires_in")
    if isinstance(expires_in, (int, float)) and expires_in > 0:
        expiry_time = int(time.time()) + int(expires_in)
    else:
        expiry_time = int(time.time()) + 7 * 3600  # default: 7 hours

    # Fetch organizationGuid from renewalRelationships
    try:
        renewal_resp = await _http.get(
            f"{API_BASE_URL}/persons/{person_guid}/renewalRelationships",
            headers={
                "Authorization": f"Bearer {token}",
                "User-Agent": USER_AGENT,
                "Accept": "application/json",
            },
        )
    except httpx.TimeoutException:
        raise RuntimeError("Login succeeded but timed out fetching organization info. Please try again.")
    except httpx.ConnectError:
        raise RuntimeError("Login succeeded but unable to reach BSA API for organization info.")

    if renewal_resp.status_code >= 400:
        raise RuntimeError(f"Login succeeded but failed to fetch organization info ({renewal_resp.status_code})")

    renewal_data = renewal_resp.json()
    organization_guid = None
    for entry in renewal_data:
        if entry.get("relationshipTypeId") is None:
            organization_guid = entry.get("organizationGuid")
            break

    if not organization_guid:
        raise RuntimeError("No organizationGuid found with null relationshipTypeId")

    logger.info("BSA login successful for user=%s*** personGuid=%s", username[:2] if len(username) >= 2 else username, person_guid)
    logger.debug("BSA login successful for user=%s personGuid=%s", username, person_guid)
    return {
        "token": token,
        "userId": str(user_id),
        "personGuid": person_guid,
        "organizationGuid": organization_guid,
        "expiryTime": expiry_time,
        "username": username,
    }


def get_auth() -> dict:
    """Retrieve BSA auth state for the current request's MCP access token."""
    from fastmcp.server.dependencies import get_access_token

    access_token = get_access_token()
    if not access_token:
        raise RuntimeError(
            "Not authenticated. Please sign in through the OAuth login flow."
        )

    session = _auth_sessions.get(access_token.token)
    if not session:
        raise RuntimeError(
            "Not authenticated. Please sign in through the OAuth login flow."
        )

    now = int(time.time())
    if session.get("expiryTime", 0) <= now + 300:
        _auth_sessions.pop(access_token.token, None)
        raise RuntimeError(
            "Session expired. Please re-authenticate through the OAuth login flow."
        )

    logger.debug("Auth resolved for user=%s token=...%s", session.get("username"), access_token.token[-6:])
    return session


async def set_auth(mcp_token: str, auth: dict):
    """Store BSA auth state keyed by MCP access token (write-through to disk)."""
    _auth_sessions[mcp_token] = auth
    logger.info("Session stored for user=%s token=...%s", auth.get("username"), mcp_token[-6:])

    try:
        store = await get_store()
        ttl = max(0, auth.get("expiryTime", 0) - int(time.time()))
        await store.put(mcp_token, auth, collection="sessions", ttl=ttl)
    except Exception:
        logger.warning("Failed to persist session to store", exc_info=True)


async def clear_auth(mcp_token: str):
    """Clear BSA auth state for a specific MCP access token."""
    session = _auth_sessions.pop(mcp_token, None)
    if session:
        logger.info("Session cleared for user=%s token=...%s", session.get("username"), mcp_token[-6:])

    try:
        store = await get_store()
        await store.delete(mcp_token, collection="sessions")
    except Exception:
        logger.warning("Failed to delete session from store", exc_info=True)


async def cleanup_expired_sessions():
    """Remove expired BSA auth sessions."""
    now = int(time.time())
    expired = [k for k, v in _auth_sessions.items() if v.get("expiryTime", 0) <= now + 300]
    for k in expired:
        _auth_sessions.pop(k, None)
    if expired:
        logger.info("Cleaned up %d expired session(s)", len(expired))

    # Disk cleanup happens automatically via TTL — no explicit deletion needed
