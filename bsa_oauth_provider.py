import asyncio
import html
import json
import logging
import os
import re
import secrets
import string
import time

from fastmcp.server.auth import OAuthProvider, AccessToken
from mcp.server.auth.provider import (
    AuthorizationCode,
    AuthorizationParams,
    RefreshToken,
    TokenError,
    construct_redirect_uri,
)
from mcp.server.auth.settings import ClientRegistrationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.requests import Request
from starlette.responses import HTMLResponse
from starlette.routing import Route

from auth import login, set_auth, clear_auth, cleanup_expired_sessions, ensure_sessions_loaded
from store import get_store, load_collection

logger = logging.getLogger("scoutbook.oauth")

try:
    AUTH_CODE_TTL = int(os.environ.get("AUTH_CODE_TTL", "300"))
except (ValueError, TypeError):
    AUTH_CODE_TTL = 300

try:
    TRANSACTION_TTL = int(os.environ.get("TRANSACTION_TTL", "900"))
except (ValueError, TypeError):
    TRANSACTION_TTL = 900
CLEANUP_INTERVAL = 300  # 5 minutes


SUCCESS_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Login Successful</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #f0f2f5;
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 100vh;
  }
  .card {
    background: #fff;
    border-radius: 8px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    padding: 2rem;
    width: 100%;
    max-width: 400px;
    text-align: center;
  }
  .checkmark {
    font-size: 3rem;
    color: #16a34a;
    margin-bottom: 0.5rem;
  }
  .card h1 {
    font-size: 1.4rem;
    color: #16a34a;
    margin-bottom: 0.5rem;
  }
  .card p {
    font-size: 0.9rem;
    color: #666;
    margin-bottom: 0.5rem;
  }
  .fallback {
    display: none;
    margin-top: 1rem;
    font-size: 0.85rem;
  }
  .fallback a { color: #003f87; }
</style>
</head>
<body>
<div class="card">
  <div class="checkmark">&#10003;</div>
  <h1>Login Successful</h1>
  <p>Returning to your MCP client...</p>
  <p class="fallback" id="fallback">
    If this window did not close, you may
    <a href="$redirect_url_html">continue manually</a>
    and then close this tab.
  </p>
</div>
<script>
  setTimeout(function() {
    window.location.href = $redirect_url_js;
  }, 500);
  // Only show fallback if we're still here after 5 seconds
  setTimeout(function() {
    document.getElementById('fallback').style.display = 'block';
  }, 5000);
</script>
<noscript><meta http-equiv="refresh" content="2;url=$redirect_url_html"></noscript>
</body>
</html>
"""


LOGIN_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BSA Login</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #f0f2f5;
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 100vh;
  }
  .card {
    background: #fff;
    border-radius: 8px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    padding: 2rem;
    width: 100%;
    max-width: 400px;
  }
  .card h1 {
    font-size: 1.4rem;
    color: #003f87;
    margin-bottom: 0.25rem;
    text-align: center;
  }
  .card p.subtitle {
    font-size: 0.85rem;
    color: #666;
    margin-bottom: 1.5rem;
    text-align: center;
  }
  label {
    display: block;
    font-size: 0.85rem;
    font-weight: 600;
    color: #333;
    margin-bottom: 0.25rem;
  }
  input[type="text"], input[type="password"] {
    width: 100%;
    padding: 0.6rem 0.75rem;
    border: 1px solid #ccc;
    border-radius: 4px;
    font-size: 0.95rem;
    margin-bottom: 1rem;
  }
  input:focus { outline: none; border-color: #003f87; }
  button {
    width: 100%;
    padding: 0.7rem;
    background: #003f87;
    color: #fff;
    border: none;
    border-radius: 4px;
    font-size: 1rem;
    cursor: pointer;
    font-weight: 600;
  }
  button:hover { background: #002a5c; }
  .error {
    background: #fef2f2;
    color: #b91c1c;
    padding: 0.6rem 0.75rem;
    border-radius: 4px;
    font-size: 0.85rem;
    margin-bottom: 1rem;
    border: 1px solid #fecaca;
    text-align: left;
    line-height: 1.5;
  }
  .error ol { margin: 0.4rem 0 0 1.2rem; }
  .error li { margin-bottom: 0.2rem; }
  .error a { color: #b91c1c; font-weight: 600; }
</style>
</head>
<body>
<div class="card">
  <h1>BSA Scoutbook Login</h1>
  <p class="subtitle">Sign in with your my.scouting.org credentials</p>
  $error_html
  <form method="post" action="/bsa-login">
    <input type="hidden" name="txn_id" value="$txn_id">
    <input type="hidden" name="csrf_token" value="$csrf_token">
    <label for="username">Username</label>
    <input type="text" id="username" name="username" autocomplete="username" required>
    <label for="password">Password</label>
    <input type="password" id="password" name="password" autocomplete="current-password" required>
    <button type="submit">Sign In</button>
  </form>
</div>
<script>
  document.querySelector('form').addEventListener('submit', function() {
    var btn = this.querySelector('button[type="submit"]');
    btn.disabled = true;
    btn.textContent = 'Signing in\u2026';
  });
</script>
</body>
</html>
"""


def _with_flexible_localhost_redirect(
    client: OAuthClientInformationFull,
) -> OAuthClientInformationFull:
    """Patch a client so that ``validate_redirect_uri`` accepts any localhost port."""
    if not client.redirect_uris:
        return client

    has_localhost = any(
        re.match(r"^https?://localhost(:\d+)?(/|$)", str(uri))
        for uri in client.redirect_uris
    )
    if not has_localhost:
        return client

    _original_validate = client.validate_redirect_uri

    def _flexible_validate(redirect_uri):
        if redirect_uri is not None and re.match(
            r"^https?://localhost(:\d+)?(/|$)", str(redirect_uri)
        ):
            return redirect_uri
        return _original_validate(redirect_uri)

    object.__setattr__(client, "validate_redirect_uri", _flexible_validate)
    return client


class BSAOAuthProvider(OAuthProvider):
    """OAuth provider that authenticates users via BSA (auth.scouting.org)."""

    def __init__(self):
        base_url = os.environ.get("MCP_BASE_URL")
        if not base_url:
            raise RuntimeError("MCP_BASE_URL environment variable is required (e.g. https://scoutbook.example.com)")
        super().__init__(
            base_url=base_url,
            client_registration_options=ClientRegistrationOptions(enabled=True),
        )

        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.auth_codes: dict[str, AuthorizationCode] = {}
        self.access_tokens: dict[str, AccessToken] = {}
        self.transactions: dict[str, dict] = {}
        self.completed_transactions: dict[str, dict] = {}
        self.bsa_auth_by_code: dict[str, dict] = {}
        self._last_cleanup: float = 0.0
        self._loaded = False
        self._loaded_lock = asyncio.Lock()

        logger.info("BSAOAuthProvider initialized, base_url=%s", base_url)

    async def _ensure_loaded(self):
        """Populate in-memory dicts from persistent store on first access."""
        if self._loaded:
            return

        async with self._loaded_lock:
            if self._loaded:
                return

            await ensure_sessions_loaded()

            try:
                now = int(time.time())

                client_entries = await load_collection("clients")
                for key, val in client_entries:
                    try:
                        self.clients[key] = OAuthClientInformationFull.model_validate(val)
                    except Exception:
                        logger.warning("Failed to deserialize client %s", key)

                token_entries = await load_collection("tokens")
                restored_tokens = 0
                for key, val in token_entries:
                    if val.get("expires_at", 0) > now:
                        try:
                            self.access_tokens[key] = AccessToken.model_validate(val)
                            restored_tokens += 1
                        except Exception:
                            logger.warning("Failed to deserialize token ...%s", key[-6:])

                logger.info(
                    "Restored %d client(s) and %d token(s) from persistent store",
                    len(client_entries), restored_tokens,
                )
            except Exception:
                logger.warning("Failed to load state from persistent store", exc_info=True)
            finally:
                self._loaded = True

    async def _cleanup(self):
        """Remove expired transactions, auth codes, tokens, and sessions."""
        now = time.time()

        expired_txns = [k for k, v in self.transactions.items()
                        if now - v["created_at"] > TRANSACTION_TTL]
        for k in expired_txns:
            del self.transactions[k]

        expired_completed = [k for k, v in self.completed_transactions.items()
                             if now - v["time"] > TRANSACTION_TTL]
        for k in expired_completed:
            del self.completed_transactions[k]

        expired_codes = [k for k, v in self.auth_codes.items()
                         if v.expires_at < now]
        for k in expired_codes:
            del self.auth_codes[k]
            self.bsa_auth_by_code.pop(k, None)

        expired_tokens = [k for k, v in self.access_tokens.items()
                          if v.expires_at is not None and v.expires_at < now]
        for k in expired_tokens:
            del self.access_tokens[k]

        await cleanup_expired_sessions()

        self._last_cleanup = now
        if expired_txns or expired_codes or expired_tokens:
            logger.info(
                "Cleanup: %d txns, %d codes, %d tokens removed",
                len(expired_txns), len(expired_codes), len(expired_tokens),
            )

    async def _maybe_cleanup(self):
        if time.time() - self._last_cleanup > CLEANUP_INTERVAL:
            await self._cleanup()

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        await self._ensure_loaded()
        client = self.clients.get(client_id)
        if client:
            return _with_flexible_localhost_redirect(client)

        try:
            store = await get_store()
            val = await store.get(client_id, collection="clients")
            if val:
                client = OAuthClientInformationFull.model_validate(val)
                self.clients[client_id] = client
                return _with_flexible_localhost_redirect(client)
        except Exception:
            logger.warning("Failed to load client %s from store", client_id, exc_info=True)

        return None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if client_info.client_id is None:
            raise ValueError("client_id is required")
        client_info.token_endpoint_auth_method = "none"
        client_info.client_secret = None
        client_info.client_secret_expires_at = None
        self.clients[client_info.client_id] = client_info
        logger.info(
            "Client registered: %s (auth_method=%s, has_secret=%s)",
            client_info.client_id,
            client_info.token_endpoint_auth_method,
            client_info.client_secret is not None,
        )

        try:
            store = await get_store()
            await store.put(
                client_info.client_id,
                client_info.model_dump(mode="json"),
                collection="clients",
            )
        except Exception:
            logger.warning("Failed to persist client %s to store", client_info.client_id, exc_info=True)

    async def authorize(
        self,
        client: OAuthClientInformationFull,
        params: AuthorizationParams,
    ) -> str:
        await self._ensure_loaded()
        await self._maybe_cleanup()

        txn_id = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        self.transactions[txn_id] = {
            "client_id": client.client_id,
            "redirect_uri": str(params.redirect_uri),
            "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
            "state": params.state,
            "scopes": params.scopes or [],
            "code_challenge": params.code_challenge,
            "created_at": time.time(),
            "csrf_token": csrf_token,
        }
        redirect = f"{str(self.base_url).rstrip('/')}/bsa-login?txn_id={txn_id}"
        logger.info("OAuth authorize: client=%s txn=%s redirect=%s", client.client_id, txn_id, redirect)
        return redirect

    async def load_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: str,
    ) -> AuthorizationCode | None:
        code_obj = self.auth_codes.get(authorization_code)
        if not code_obj:
            return None
        if code_obj.client_id != client.client_id:
            logger.warning("Auth code client_id mismatch: expected=%s got=%s", code_obj.client_id, client.client_id)
            return None
        if code_obj.expires_at < time.time():
            self.auth_codes.pop(authorization_code, None)
            self.bsa_auth_by_code.pop(authorization_code, None)
            logger.warning("Auth code expired for client=%s", client.client_id)
            return None
        return code_obj

    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        if authorization_code.code not in self.auth_codes:
            raise TokenError("invalid_grant", "Authorization code not found or already used.")

        del self.auth_codes[authorization_code.code]

        bsa_auth = self.bsa_auth_by_code.pop(authorization_code.code, None)
        if not bsa_auth:
            raise TokenError("invalid_grant", "BSA authentication data not found for this code.")

        remaining_seconds = max(0, bsa_auth["expiryTime"] - int(time.time()))

        access_token_value = secrets.token_urlsafe(48)
        expires_at = int(time.time()) + remaining_seconds

        token_obj = AccessToken(
            token=access_token_value,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=expires_at,
        )
        self.access_tokens[access_token_value] = token_obj

        await set_auth(access_token_value, bsa_auth)

        try:
            store = await get_store()
            await store.put(
                access_token_value,
                token_obj.model_dump(mode="json"),
                collection="tokens",
                ttl=remaining_seconds,
            )
        except Exception:
            logger.warning("Failed to persist access token to store", exc_info=True)

        logger.info(
            "Token issued for user=%s client=%s expires_in=%ds token=...%s",
            bsa_auth.get("username"), client.client_id, remaining_seconds, access_token_value[-6:],
        )

        return OAuthToken(
            access_token=access_token_value,
            token_type="Bearer",
            expires_in=remaining_seconds,
            scope=" ".join(authorization_code.scopes) if authorization_code.scopes else None,
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        await self._ensure_loaded()
        await self._maybe_cleanup()
        token_obj = self.access_tokens.get(token)
        if token_obj:
            if token_obj.expires_at is not None and token_obj.expires_at < time.time():
                self.access_tokens.pop(token, None)
                logger.info("Access token expired, removed token=...%s", token[-6:])
                return None
            return token_obj

        try:
            store = await get_store()
            val = await store.get(token, collection="tokens")
            if val and val.get("expires_at", 0) > time.time():
                token_obj = AccessToken.model_validate(val)
                self.access_tokens[token] = token_obj
                return token_obj
        except Exception:
            logger.warning("Failed to load token from store", exc_info=True)

        return None

    async def verify_token(self, token: str) -> AccessToken | None:
        return await self.load_access_token(token)

    async def load_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: str,
    ) -> RefreshToken | None:
        return None

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        raise TokenError("unsupported_grant_type", "Refresh tokens are not supported. Please re-authenticate.")

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        if isinstance(token, AccessToken):
            self.access_tokens.pop(token.token, None)
            await clear_auth(token.token)
            logger.info("Token revoked: ...%s", token.token[-6:])

            try:
                store = await get_store()
                await store.delete(token.token, collection="tokens")
            except Exception:
                logger.warning("Failed to delete token from store", exc_info=True)

    @staticmethod
    def _error_page(message: str, status_code: int = 400, hint: str = "") -> HTMLResponse:
        escaped = html.escape(message)
        hint_html = f'<p class="hint">{html.escape(hint)}</p>' if hint else ""
        page = f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Error</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #f0f2f5;
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 100vh;
  }}
  .card {{
    background: #fff;
    border-radius: 8px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    padding: 2rem;
    width: 100%;
    max-width: 400px;
    text-align: center;
  }}
  .icon {{ font-size: 3rem; color: #b91c1c; margin-bottom: 0.5rem; }}
  .card h1 {{ font-size: 1.4rem; color: #b91c1c; margin-bottom: 0.5rem; }}
  .card p {{ font-size: 0.9rem; color: #666; margin-bottom: 0.5rem; line-height: 1.5; }}
  .hint {{ font-size: 0.85rem; color: #555; background: #f9fafb; border: 1px solid #e5e7eb;
           border-radius: 6px; padding: 0.75rem; margin-top: 0.75rem; text-align: left; }}
</style>
</head>
<body>
<div class="card">
  <div class="icon">&#x26A0;</div>
  <h1>Error</h1>
  <p>{escaped}</p>
  {hint_html}
</div>
</body>
</html>"""
        return HTMLResponse(page, status_code=status_code)

    @staticmethod
    def _success_page(redirect_url: str | None = None) -> HTMLResponse:
        if redirect_url:
            page = string.Template(SUCCESS_HTML).safe_substitute(
                redirect_url_js=json.dumps(redirect_url),
                redirect_url_html=html.escape(redirect_url, quote=True),
            )
            return HTMLResponse(page, status_code=200)
        return HTMLResponse(
            "<h1>Login Successful</h1>"
            "<p>You have been authenticated. You can close this window.</p>",
            status_code=200,
        )

    _SESSION_HINT = (
        "This app requires Scouting America credentials (not Google or Apple sign-in). "
        "If you haven't set one up, go to my.scouting.org/tools/my-account, "
        "select \"Scouting America Credentials\" under Account, and set a password. "
        "Then go back to the app and click Login to try again."
    )

    def _validate_transaction(self, txn_id: str) -> dict | HTMLResponse:
        if not txn_id:
            return self._error_page(
                "Your login session is invalid. Please go back to the app and click Login to start over.",
                hint=self._SESSION_HINT,
            )
        if txn_id in self.completed_transactions:
            logger.info("Duplicate submission for already-completed txn=%s", txn_id)
            return self._success_page(self.completed_transactions[txn_id].get("redirect_url"))
        if txn_id not in self.transactions:
            return self._error_page(
                "Your login session has expired. Please go back to the app and click Login to start over.",
                hint=self._SESSION_HINT,
            )
        txn = self.transactions[txn_id]
        if time.time() - txn["created_at"] > TRANSACTION_TTL:
            self.transactions.pop(txn_id, None)
            return self._error_page(
                "Your login session has expired. Please go back to the app and click Login to start over.",
                hint=self._SESSION_HINT,
            )
        return txn

    def get_routes(self, **kwargs) -> list[Route]:
        routes = super().get_routes(**kwargs)
        routes.append(
            Route(
                path="/bsa-login",
                endpoint=self._handle_bsa_login,
                methods=["GET", "POST"],
            )
        )
        return routes

    async def _handle_bsa_login(self, request: Request) -> HTMLResponse:
        if request.method == "POST":
            return await self._submit_bsa_login(request)
        return await self._show_bsa_login(request)

    async def _show_bsa_login(
        self, request: Request, error_message: str | None = None,
        error_html_override: str | None = None, txn_id: str | None = None,
    ) -> HTMLResponse:
        if txn_id is None:
            txn_id = request.query_params.get("txn_id", "")
        result = self._validate_transaction(txn_id)
        if isinstance(result, HTMLResponse):
            return result
        txn = result

        if error_html_override:
            error_html = f'<div class="error">{error_html_override}</div>'
        elif error_message:
            error_html = f'<div class="error">{html.escape(error_message)}</div>'
        else:
            error_html = ""
        page = string.Template(LOGIN_HTML).safe_substitute(
            txn_id=txn_id,
            csrf_token=txn["csrf_token"],
            error_html=error_html,
        )
        return HTMLResponse(page)

    async def _submit_bsa_login(self, request: Request) -> HTMLResponse:
        form = await request.form()
        txn_id = str(form.get("txn_id", ""))
        csrf_token = str(form.get("csrf_token", ""))
        username = str(form.get("username", "")).strip()
        password = str(form.get("password", ""))

        result = self._validate_transaction(txn_id)
        if isinstance(result, HTMLResponse):
            return result
        txn = result

        if not csrf_token or csrf_token != txn.get("csrf_token"):
            logger.warning("CSRF token mismatch for txn=%s", txn_id)
            return self._error_page("Invalid form submission. Please retry from your MCP client.")

        if not username or not password:
            return await self._show_bsa_login(request, error_message="Username and password are required.", txn_id=txn_id)

        self.transactions.pop(txn_id, None)

        try:
            bsa_auth = await login(username, password)
        except RuntimeError as e:
            error_code = str(e)
            if error_code == "LOGIN_FORBIDDEN":
                forbidden_html = (
                    "Your credentials were rejected by BSA.<br><br>"
                    "If you normally sign in to my.scouting.org with <strong>Google</strong> or "
                    "<strong>Apple</strong>, you&#39;ll need to set up a Scouting America password first:"
                    "<ol>"
                    '<li>Go to <a href="https://my.scouting.org/tools/my-account" target="_blank">'
                    "my.scouting.org/tools/my-account</a></li>"
                    '<li>Select <strong>"Scouting America Credentials"</strong> under Account</li>'
                    "<li>Set a password</li>"
                    "<li>Come back here and log in with your <strong>User Name</strong> and that password</li>"
                    "</ol>"
                )
                logger.warning("Login failed for user=%s: %s", username, error_code)
                txn["created_at"] = time.time()
                self.transactions[txn_id] = txn
                return await self._show_bsa_login(request, error_html_override=forbidden_html, txn_id=txn_id)
            elif error_code == "LOGIN_UNAUTHORIZED":
                error_msg = "Invalid username or password. Please try again."
            elif error_code.startswith("LOGIN_ERROR:"):
                error_msg = f"BSA login service returned an error ({error_code.split(':')[1]}). Please try again later."
            else:
                error_msg = str(e)
            logger.warning("Login failed for user=%s: %s", username, error_code)
            txn["created_at"] = time.time()
            self.transactions[txn_id] = txn
            return await self._show_bsa_login(request, error_message=error_msg, txn_id=txn_id)
        except Exception:
            logger.exception("Unexpected error during BSA login for user=%s", username)
            txn["created_at"] = time.time()
            self.transactions[txn_id] = txn
            return await self._show_bsa_login(
                request, error_message="An unexpected error occurred. Please try again.", txn_id=txn_id,
            )

        auth_code_value = secrets.token_urlsafe(32)

        redirect_url = construct_redirect_uri(
            txn["redirect_uri"], code=auth_code_value, state=txn["state"]
        )

        self.completed_transactions[txn_id] = {"time": time.time(), "redirect_url": redirect_url}
        auth_code = AuthorizationCode(
            code=auth_code_value,
            client_id=txn["client_id"],
            redirect_uri=txn["redirect_uri"],
            redirect_uri_provided_explicitly=txn["redirect_uri_provided_explicitly"],
            scopes=txn["scopes"],
            expires_at=time.time() + AUTH_CODE_TTL,
            code_challenge=txn["code_challenge"],
        )

        self.auth_codes[auth_code_value] = auth_code
        self.bsa_auth_by_code[auth_code_value] = bsa_auth

        logger.info("Auth code issued for user=%s client=%s", username, txn["client_id"])

        return self._success_page(redirect_url=redirect_url)
