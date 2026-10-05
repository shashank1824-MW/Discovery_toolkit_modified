from fastapi import APIRouter, HTTPException, Body
from pydantic import BaseModel
import httpx
import logging
import asyncio
from typing import Optional, Dict, Any, List
import uuid
import re as re_module

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/toolkit/discovery", tags=["Internal Tools"])

import hashlib
import time

# Global Enrichment Cache (Task 3)
# Key: (token_hash, company_id)
# Value: {"user_map": ..., "unique_count": ..., "search_map": ..., "timestamp": ...}
ENRICHMENT_CACHE = {}
CACHE_TTL = 600  # 10 minutes

WORKSPACE_CACHE: Dict[str, Dict[str, Dict[str, Any]]] = {}
WORKSPACE_CACHE_TTL = 600


# ─── Run Event Store (Phase 3: Observability) ────────────────────────────────

RUN_EVENTS_ENABLED = True  # Feature flag: DISCOVERY_RUN_EVENTS_ENABLED
MAX_RUNS = 100
RUN_TTL = 600  # 10 minutes

# In-memory store: run_id -> {"events": [], "status": str, "summary": {}, "created_at": float}
RUN_STORE: Dict[str, Dict[str, Any]] = {}

# Patterns to redact from event context
SENSITIVE_PATTERNS = [
    re_module.compile(r"(Bearer\s+)[A-Za-z0-9\-._~+/]+=*", re_module.IGNORECASE),
    re_module.compile(r"(eyJ[A-Za-z0-9\-._~+/]+=*)", re_module.IGNORECASE),
]
SENSITIVE_KEYS = {
    "authorization",
    "token",
    "cookie",
    "set-cookie",
    "x-api-key",
    "secret",
    "password",
    "access_token",
}


def redact_sensitive(data: Any) -> Any:
    """Recursively redact sensitive values from dicts/lists for safe logging."""
    if isinstance(data, dict):
        return {
            k: "[REDACTED]" if k.lower() in SENSITIVE_KEYS else redact_sensitive(v)
            for k, v in data.items()
        }
    elif isinstance(data, list):
        return [redact_sensitive(item) for item in data]
    elif isinstance(data, str):
        result = data
        for pattern in SENSITIVE_PATTERNS:
            result = pattern.sub(
                lambda m: m.group(1) + "[REDACTED]" if m.lastindex else "[REDACTED]",
                result,
            )
        return result
    return data


def cleanup_run_store():
    """Evict expired or oldest runs to stay under MAX_RUNS."""
    now = time.time()
    # Remove expired runs
    expired = [
        rid
        for rid, rdata in RUN_STORE.items()
        if now - rdata.get("created_at", 0) > RUN_TTL
    ]
    for rid in expired:
        del RUN_STORE[rid]
    # If still over limit, remove oldest
    while len(RUN_STORE) > MAX_RUNS:
        oldest_id = min(RUN_STORE, key=lambda rid: RUN_STORE[rid].get("created_at", 0))
        del RUN_STORE[oldest_id]


def emit_run_event(
    run_id: str, stage: str, severity: str, message: str, context: Optional[Dict] = None
):
    """Append an event to the run store (if the run exists and feature is enabled)."""
    if not RUN_EVENTS_ENABLED or run_id not in RUN_STORE:
        return
    event = {
        "run_id": run_id,
        "timestamp": time.time(),
        "stage": stage,
        "severity": severity,
        "message": message,
        "context": redact_sensitive(context) if context else None,
    }
    RUN_STORE[run_id]["events"].append(event)
    # Cap events per run at 500
    if len(RUN_STORE[run_id]["events"]) > 500:
        RUN_STORE[run_id]["events"] = RUN_STORE[run_id]["events"][-500:]


def start_run(preset_name: str = "unknown", run_id: Optional[str] = None) -> str:
    """Create a new run in the store. Returns the run_id."""
    if not RUN_EVENTS_ENABLED:
        return ""
    cleanup_run_store()
    if not run_id:
        run_id = f"run_{int(time.time())}_{uuid.uuid4().hex[:8]}"
    RUN_STORE[run_id] = {
        "events": [],
        "status": "running",
        "summary": {"preset": preset_name},
        "created_at": time.time(),
    }
    return run_id


def finish_run(run_id: str, status: str, summary_extra: Optional[Dict] = None):
    """Mark a run as completed or failed with optional summary metadata."""
    if not RUN_EVENTS_ENABLED or run_id not in RUN_STORE:
        return
    RUN_STORE[run_id]["status"] = status
    RUN_STORE[run_id]["summary"]["finished_at"] = time.time()
    RUN_STORE[run_id]["summary"]["duration_ms"] = int(
        (time.time() - RUN_STORE[run_id]["created_at"]) * 1000
    )
    if summary_extra:
        RUN_STORE[run_id]["summary"].update(summary_extra)


@router.get("/execute/{run_id}/events")
async def get_run_events(run_id: str):
    """Polling endpoint: returns the event timeline and status for a specific run."""
    if not RUN_EVENTS_ENABLED:
        return {"error": True, "message": "Run events are disabled"}
    if run_id not in RUN_STORE:
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
    run_data = RUN_STORE[run_id]
    return {
        "run_id": run_id,
        "status": run_data["status"],
        "events": run_data["events"],
        "summary": run_data["summary"],
    }


def get_cache_key(token: str, company_id: Optional[str]) -> str:
    """Generates a stable cache key using token hash and company ID"""
    token_hash = hashlib.sha256(token.encode()).hexdigest()[:16]
    return f"{token_hash}_{company_id or 'default'}"


class ContextSwitchRequest(BaseModel):
    masterToken: str
    targetCompanyId: str
    sessionCookies: Optional[Dict[str, str]] = (
        None  # Cookies from Chrome extension for session context
    )


@router.post("/switch-context")
async def switch_context(payload: ContextSwitchRequest):
    """
    Advanced switch context with SSO handshake completion and baseline diagnostics.
    """
    import urllib.parse
    import json
    import jwt
    import re
    from httpx import Cookies

    logger.info(
        f"=== SSO HANDSHAKE CONTEXT SWITCH START ({payload.targetCompanyId}) ==="
    )

    # Session Info - decode master token to get current company
    old_company_id = "unknown"
    token_expiry = None
    try:
        old_payload = jwt.decode(
            payload.masterToken, options={"verify_signature": False}
        )
        old_company_id = old_payload.get("company", {}).get("_id") or old_payload.get(
            "user", {}
        ).get("activeCompanyId")
        token_expiry = old_payload.get("exp")
        logger.info(
            f"  [Token Info] Current company: {old_company_id}, Expiry: {token_expiry}"
        )
    except Exception as e:
        logger.info(f"  [Token Info] Error decoding master token: {e}")
        return {"success": False, "message": "Invalid master token format"}

    # Baseline Diagnostic - check if token works with app subdomain (not API)
    logger.info("  [Baseline] Verifying Master Token via app subdomain...")
    token_valid = False
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Try the app subdomain which might accept session tokens
            me_resp = await client.get(
                "https://app.meltwater.com/api/idp/me",
                headers={"Authorization": f"Bearer {payload.masterToken}"},
                follow_redirects=True,
            )
            logger.info(f"  [Baseline] App /me Result: {me_resp.status_code}")
            if me_resp.status_code == 200:
                token_valid = True
    except Exception as e:
        logger.info(f"  [Baseline] App verifier error: {e}")

    # Also try API endpoint
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            me_resp = await client.get(
                "https://api.meltwater.com/v3/accounts/me/companies",
                headers={"Authorization": f"Bearer {payload.masterToken}"},
            )
            logger.info(f"  [Baseline] API /companies Result: {me_resp.status_code}")
            if me_resp.status_code == 200:
                token_valid = True
    except Exception as e:
        logger.info(f"  [Baseline] API verifier error: {e}")

    if not token_valid:
        logger.warning(
            "  [WARNING] Master token appears invalid or expired for API calls, but web flow may still work."
        )

    # Encoding
    json_encoded = urllib.parse.quote(
        json.dumps({"token": payload.masterToken}, separators=(",", ":"))
    )

    base_headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Referer": "https://app.meltwater.com/",
        "Origin": "https://app.meltwater.com",
    }

    # Define token validation function at switch_context scope so it's accessible to all flows
    def get_validated_token(t_raw, log_prefix=""):
        try:
            if not t_raw:
                return None
            # Handle both string and bytes
            if isinstance(t_raw, bytes):
                t_raw = t_raw.decode("utf-8")

            # Log input length for debugging (truncated for readability)
            logger.info(f"    {log_prefix}Token input length: {len(t_raw)}")

            # URL decode
            dec = urllib.parse.unquote(t_raw)

            # Remove surrounding quotes if present
            if dec.startswith('"') and dec.endswith('"'):
                dec = dec[1:-1]

            t_str = ""
            # Try to parse as JSON {"token": "eyJ..."}
            if dec.startswith("{"):
                try:
                    json_data = json.loads(dec)
                    t_str = json_data.get("token", "")
                    # Also check for nested token structures
                    if not t_str and "accessToken" in json_data:
                        t_str = json_data.get("accessToken", "")
                    logger.info(
                        f"    {log_prefix}Extracted token from JSON, length: {len(t_str) if t_str else 0}"
                    )
                except json.JSONDecodeError as je:
                    logger.info(
                        f"    {log_prefix}JSON parse error: {je}, trying raw decode..."
                    )
                    # Try to extract JWT directly from the string
                    jwt_match = re.search(
                        r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
                        dec,
                    )
                    if jwt_match:
                        t_str = jwt_match.group(0)
                        logger.info(
                            f"    {log_prefix}Extracted token via regex, length: {len(t_str)}"
                        )
            elif dec.startswith("eyJ"):
                t_str = dec
                logger.info(f"    {log_prefix}Token is raw JWT, length: {len(t_str)}")

            # Validate and decode the JWT
            if t_str and t_str.startswith("eyJ"):
                try:
                    p = jwt.decode(t_str, options={"verify_signature": False})
                    found_cid = (
                        p.get("company", {}).get("_id")
                        or p.get("user", {}).get("activeCompanyId")
                        or p.get("cid")
                    )
                    logger.info(
                        f"    {log_prefix}Token decoded: company={found_cid}, old_company={old_company_id}"
                    )
                    # Accept ANY token that is NOT from the original company
                    if found_cid and str(found_cid) != str(old_company_id):
                        logger.info(
                            f"    {log_prefix}[NEW COMPANY TOKEN] Found: {found_cid} (target URL ID was: {payload.targetCompanyId})"
                        )
                        return t_str
                    elif found_cid:
                        logger.info(
                            f"    {log_prefix}[SKIP] Still on old company: {found_cid}"
                        )
                except Exception as jwt_e:
                    logger.info(f"    {log_prefix}JWT decode error: {jwt_e}")
            else:
                logger.info(f"    {log_prefix}No valid JWT found in input")
        except Exception as e:
            logger.info(
                f"    {log_prefix}Token validation error: {type(e).__name__}: {e}"
            )
        return None

    async def try_flow(
        name,
        url,
        method="GET",
        use_auth_header=True,
        cookie_val=None,
        json_body=None,
        session_cookies=None,
    ):
        logger.info(f"--- ATTEMPT: {name} ---")
        jar = Cookies()

        # Use session cookies from Chrome extension if provided
        if session_cookies:
            logger.info(f"  [{name}] Using session cookies from Chrome extension")
            if "gydaToken" in session_cookies:
                jar.set(
                    "gydaToken",
                    session_cookies["gydaToken"],
                    domain=".meltwater.com",
                    path="/",
                )
            if "memory" in session_cookies:
                jar.set(
                    "memory",
                    session_cookies["memory"],
                    domain=".meltwater.com",
                    path="/",
                )
            if "gydaRemember" in session_cookies:
                jar.set(
                    "gydaRemember",
                    session_cookies["gydaRemember"],
                    domain=".meltwater.com",
                    path="/",
                )
        elif cookie_val:
            jar.set("gydaToken", cookie_val, domain=".meltwater.com", path="/")
            jar.set("memory", "true", domain=".meltwater.com", path="/")
            jar.set(
                "gydaRemember", "1", domain=".meltwater.com", path="/"
            )  # Important for context switch!

        headers = {**base_headers}
        if use_auth_header:
            headers["Authorization"] = f"Bearer {payload.masterToken}"
        if json_body:
            headers["Content-Type"] = "application/json"

        def log_cookies_and_headers(resp, label):
            # Import re here to avoid scope issues
            import re as regex

            # Log Set-Cookie headers from the response
            set_cookie_headers = (
                resp.headers.get_list("set-cookie")
                if hasattr(resp.headers, "get_list")
                else [resp.headers.get("set-cookie", "")]
            )
            for sc in set_cookie_headers:
                if sc:
                    logger.info(f"    [{label}] Set-Cookie: {sc[:200]}")
            # Log all cookies in jar
            jar_cookies = (
                {c.name: c.value[:80] for c in resp.cookies.jar}
                if hasattr(resp, "cookies")
                else {}
            )
            if jar_cookies:
                logger.info(f"    [{label}] Response Cookies: {jar_cookies}")
            # Scan body for JWT tokens
            try:
                body_text = resp.text[:5000]
                jwt_hits = regex.findall(
                    r"eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}",
                    body_text,
                )
                logger.info(f"    [{label}] Found {len(jwt_hits)} JWT patterns in body")
                for hit in jwt_hits[:5]:
                    result = get_validated_token(hit, f"[{label}-body] ")
                    if result:
                        logger.info(f"    [{label}] *** JWT FOUND IN BODY! ***")
                        return result
                if jwt_hits:
                    logger.info(
                        f"    [{label}] Body has JWTs but none match target. Count: {len(jwt_hits)}"
                    )
            except Exception as e:
                logger.info(f"    [{label}] Error scanning body: {e}")
            return None

        try:
            async with httpx.AsyncClient(
                cookies=jar, follow_redirects=True, timeout=20.0
            ) as client:
                # Step 1: Follow the tempLogin redirect chain completely
                if method.upper() == "GET":
                    resp = await client.get(url, headers=headers)
                else:
                    resp = await client.post(url, headers=headers, json=json_body)

                logger.info(f"  [{name}] Final Step | {resp.status_code} | {resp.url}")

                # Get all cookies with FULL values for validation (don't truncate!)
                all_jar_cookies_full = {c.name: c.value for c in client.cookies.jar}
                logger.info(
                    f"  [{name}] Jar Cookies After tempLogin: {list(all_jar_cookies_full.keys())}"
                )
                for c_name, c_val in all_jar_cookies_full.items():
                    logger.info(f"    [{name}] Cookie {c_name}: {c_val[:100]}...")

                # Check cookies for a valid token (use full values, not truncated)
                for c_name, c_val in all_jar_cookies_full.items():
                    v = get_validated_token(c_val, f"[{c_name}] ")
                    if v:
                        return v

                # Check body for embedded JWTs (switchingCompany page OR a/home page)
                final_url = str(resp.url)
                logger.info(f"  [{name}] Checking response body for tokens...")
                body_token = log_cookies_and_headers(resp, name)
                if body_token:
                    return body_token

                # If we landed at /a/home, that's good - check for tokens there
                if "/a/home" in final_url:
                    logger.info(f"  [{name}] At /a/home, checking for tokens...")
                    # Already checked cookies above, just log the state
                    logger.info(
                        f"  [{name}] At home, cookies: {list({c.name: c.value[:50] for c in client.cookies.jar}.keys())}"
                    )

                # If we're stuck at /switchingCompany, try navigating to root first, then /a/home
                # This is the key difference between working and failing cases!
                # Working case: tempLogin → / → /a/home
                # Failing case: tempLogin → /switchingCompany (stops)
                if "/switchingCompany" in final_url:
                    logger.info(
                        f"  [{name}] At switchingCompany, trying root → home navigation..."
                    )
                    try:
                        # First try root
                        root_resp = await client.get(
                            "https://app.meltwater.com/", headers=headers
                        )
                        logger.info(
                            f"  [{name}] Navigated to root: {root_resp.status_code} | {root_resp.url}"
                        )
                        # Check cookies after root
                        for c_name, c_val in {
                            c.name: c.value for c in client.cookies.jar
                        }.items():
                            v = get_validated_token(c_val, f"[post-root {c_name}] ")
                            if v:
                                return v

                        # Then navigate to home
                        home_resp = await client.get(
                            "https://app.meltwater.com/a/home", headers=headers
                        )
                        logger.info(
                            f"  [{name}] Navigated to home: {home_resp.status_code} | {home_resp.url}"
                        )
                        # Check cookies after navigating to home
                        for c_name, c_val in {
                            c.name: c.value for c in client.cookies.jar
                        }.items():
                            v = get_validated_token(c_val, f"[post-home {c_name}] ")
                            if v:
                                return v
                    except Exception as e:
                        logger.info(f"  [{name}] Error navigating: {e}")

                    # Also try the explicit switchingCompany endpoint with query param
                    try:
                        sc_resp = await client.get(
                            f"https://app.meltwater.com/switchingCompany?switchId={payload.targetCompanyId}",
                            headers=headers,
                        )
                        logger.info(
                            f"  [{name}] switchingCompany redirect: {sc_resp.status_code} | {sc_resp.url}"
                        )
                        # Check cookies again after navigating
                        for c_name, c_val in {
                            c.name: c.value for c in client.cookies.jar
                        }.items():
                            v = get_validated_token(c_val, f"[post-nav {c_name}] ")
                            if v:
                                return v
                    except Exception as e:
                        logger.info(
                            f"  [{name}] Error navigating to switchingCompany: {e}"
                        )

        except Exception as e:
            logger.info(f"  [{name}] FLOW ERROR: {type(e).__name__} - {e}")
        return None

    # Use session cookies from Chrome extension if available
    session_cookies = payload.sessionCookies
    if session_cookies:
        logger.info("Using session cookies from Chrome extension for context switch")

    # Single attempt: Legacy tempLogin flow
    result_token = await try_flow(
        "Legacy Full-Follow",
        f"https://app.meltwater.com/idp/tempLogin/{payload.targetCompanyId}",
        use_auth_header=True,
        cookie_val=json_encoded if not session_cookies else None,
        session_cookies=session_cookies,
    )

    if result_token:
        # Fetch company name for better success message
        company_info = await get_current_company_info(result_token)
        company_name = (
            company_info.get("name", payload.targetCompanyId)
            if company_info
            else payload.targetCompanyId
        )
        logger.info(f"=== CONTEXT SWITCH SUCCESS: {company_name} ===")
        return {
            "success": True,
            "newToken": result_token,
            "companyName": company_name,
            "message": f"Successfully switched to {company_name}",
        }

    logger.info(f"=== CONTEXT SWITCH FAILED ===")
    return {
        "success": False,
        "message": f"Unable to switch to company {payload.targetCompanyId}. Make sure you are logged into the source company and have access to the target company.",
    }


class DiscoveryRequest(BaseModel):
    token: str
    baseUrl: str
    endpoint: str
    method: str = "POST"
    headers: Optional[Dict[str, str]] = None
    body: Dict[str, Any]
    placeholders: Optional[Dict[str, str]] = None  # e.g., {"accountId": "123"}
    rawAuth: Optional[bool] = (
        False  # If True, use token directly without "Bearer " prefix
    )
    composite: Optional[Dict[str, str]] = None  # For composite presets
    run_id: Optional[str] = None  # For frontend-generated polling ID


# --- MAPPING HELPERS & WARMUP ---


async def get_user_map(
    token: str, company_id: Optional[str] = None
) -> Dict[str, Dict[str, str]]:
    """Fetches users and returns a map of id -> {name, email}"""
    cache_key = get_cache_key(token, company_id)
    if cache_key in ENRICHMENT_CACHE:
        entry = ENRICHMENT_CACHE[cache_key]
        if time.time() - entry.get("timestamp", 0) < CACHE_TTL and "user_map" in entry:
            logger.info(f"--- get_user_map CACHE HIT (company_id: {company_id}) ---")
            return entry["user_map"], entry.get("unique_count", 0)

    logger.info(f"--- get_user_map START (company_id: {company_id}) ---")

    # Use GraphQL for user fetching (more reliable and comprehensive)
    import asyncio

    graphql_task = list_users_complete_handler(token, company_id=company_id)
    res_graphql = await graphql_task

    users = []
    if not res_graphql.get("error"):
        users = res_graphql.get("data", [])
        logger.info(f"GraphQL returned {len(users)} users")
    else:
        logger.warning(f"GraphQL failed: {res_graphql.get('message')}")

    if not users:
        logger.warning(
            "No users found from GraphQL, trying Identity REST API as fallback..."
        )
        # Fallback to Identity REST if GraphQL fails completely
        identity_task = list_users_identity_handler(token, company_id=company_id)
        res_identity = await identity_task
        if not res_identity.get("error"):
            users = res_identity.get("data", [])
            logger.info(f"Identity returned {len(users)} users as fallback")

    user_map = {}
    unique_user_ids = set()
    for u in users:
        uid = u.get("_id")  # User ID
        mid = u.get("membershipId")  # Membership ID

        first = u.get("firstName", "")
        last = u.get("lastName", "")
        email = u.get("email", "")

        info = {"name": f"{first} {last}".strip() or "Unknown User", "email": email}

        if uid:
            user_map[str(uid)] = info
            unique_user_ids.add(str(uid))
        if mid:
            user_map[str(mid)] = info
            # Membership ID is tied to a user, but for counting people we use uid
            if uid:
                unique_user_ids.add(str(uid))

    # We return the actual human count, not mapping key count
    logger.info(f"Mapped {len(user_map)} keys for {len(unique_user_ids)} unique users.")
    # Save unique count in a separate variable to return it clearly
    unique_count = len(unique_user_ids)

    sample_keys = list(user_map.keys())[:20]
    # Skip the meta key if it somehow got in here, but we are about to return a tuple or dict with meta separate
    sample_names = [
        v["name"] for k, v in user_map.items() if isinstance(v, dict) and "name" in v
    ][:10]
    # logger.info(f"User map sample keys: {sample_keys}")
    # logger.info(f"User map sample names: {sample_names}")

    # Update Cache
    cache_key = get_cache_key(token, company_id)
    if cache_key not in ENRICHMENT_CACHE:
        ENRICHMENT_CACHE[cache_key] = {"timestamp": time.time()}
    ENRICHMENT_CACHE[cache_key].update(
        {
            "user_map": user_map,
            "unique_count": unique_count,
            "timestamp": time.time(),  # Refresh TTL
        }
    )

    return user_map, unique_count


async def get_search_map(
    token: str, company_id: Optional[str] = None
) -> Dict[str, str]:
    """Fetches all searches and returns a map of id -> name"""
    cache_key = get_cache_key(token, company_id)
    if cache_key in ENRICHMENT_CACHE:
        entry = ENRICHMENT_CACHE[cache_key]
        if (
            time.time() - entry.get("timestamp", 0) < CACHE_TTL
            and "search_map" in entry
        ):
            logger.info(f"--- get_search_map CACHE HIT (company_id: {company_id}) ---")
            return entry["search_map"]

    logger.info(f"--- get_search_map START (company_id: {company_id}) ---")
    search_map = {}

    import jwt

    if not company_id:
        try:
            decoded_token = jwt.decode(token, options={"verify_signature": False})
            company_id = decoded_token.get("company", {}).get(
                "_id"
            ) or decoded_token.get("user", {}).get("activeCompanyId")
            logger.info(f"Extracted company_id from token: {company_id}")
        except Exception as e:
            logger.error(f"Failed to extract company_id for searches: {e}")
            return {}

    if not company_id:
        logger.warning("No company_id available for search map")
        return {}

    async with httpx.AsyncClient(timeout=30.0) as client:
        # Use comprehensive browser-like headers for masfsearch endpoint
        headers = {
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
            "Origin": "https://app.meltwater.com",
            "Referer": "https://app.meltwater.com/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "cross-site",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
            "X-Client-Name": "mi-web-app",
            "Authorization": f"Bearer {token}",
            "sec-ch-ua": '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"macOS"',
        }

        # Regular Searches
        reg_url = (
            f"https://masfsearch.meltwater.io/masfsearch/v2/search/list/{company_id}"
        )
        logger.info(f"Fetching regular searches from {reg_url}...")
        try:
            # Use longer timeout for companies with many searches (8000+ searches may take time)
            reg_resp = await client.get(reg_url, headers=headers, timeout=60.0)
            logger.info(f"Search fetch response status: {reg_resp.status_code}")

            if reg_resp.status_code == 200:
                reg_data = reg_resp.json()
                logger.info(f"Found {len(reg_data)} regular searches")

                # Handle pagination if response contains pageInfo
                if isinstance(reg_data, dict):
                    searches_list = (
                        reg_data.get("searches") or reg_data.get("data") or []
                    )
                    page_info = reg_data.get("pageInfo", {})
                    logger.info(
                        f"Search response is dict, extracted {len(searches_list)} searches, pageInfo: {page_info}"
                    )
                else:
                    searches_list = reg_data

                for s in searches_list:
                    sid = str(s.get("savedSearchId") or s.get("id"))
                    if sid:
                        search_map[sid] = s.get("name") or s.get("searchName")
            else:
                logger.warning(
                    f"Regular search map fetch failed: {reg_resp.status_code}"
                )
                try:
                    error_body = reg_resp.text[:1000]
                    logger.warning(f"Search fetch error response: {error_body}")
                except Exception as e:
                    logger.warning(f"Could not read error response body: {e}")
        except httpx.TimeoutException as e:
            logger.error(f"Search fetch timed out after 60s: {e}")
        except httpx.HTTPStatusError as e:
            logger.error(f"Search fetch HTTP error: {e}")
        except Exception as e:
            logger.error(f"Search fetch unexpected error: {type(e).__name__}: {e}")
            logger.exception("Full search fetch exception:")

        # Update Cache
        cache_key = get_cache_key(token, company_id)
        if cache_key not in ENRICHMENT_CACHE:
            ENRICHMENT_CACHE[cache_key] = {"timestamp": time.time()}
        ENRICHMENT_CACHE[cache_key].update(
            {
                "search_map": search_map,
                "timestamp": time.time(),  # Refresh TTL
            }
        )

    return search_map


async def get_workspace_map(token: str, company_id: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    """
    Fetches all workspaces for a company and returns a map of workspaceId -> workspace metadata.
    Uses GraphQL viewer.company.workspaces query.
    Falls back to Admin Workspace for null/missing workspaceIds.

    Args:
        token: Authorization bearer token
        company_id: Company ID (extracted from token if not provided)
    """
    import jwt

    if not company_id:
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            company_id = decoded.get("company", {}).get("_id") or decoded.get("user", {}).get("activeCompanyId")
        except Exception:
            company_id = None

    if not company_id:
        logger.warning("get_workspace_map: no company_id available")
        return {}

    cache_key = f"{get_cache_key(token, company_id)}_workspace"
    now = time.time()
    cache_hit = False
    cached_workspaces = {}
    if cache_key in WORKSPACE_CACHE:
        cached = WORKSPACE_CACHE[cache_key]
        if now - cached.get("timestamp", 0) < WORKSPACE_CACHE_TTL:
            logger.info(f"--- get_workspace_map CACHE HIT (company_id: {company_id}) ---")
            return cached.get("workspaces", {})

    logger.info(f"--- get_workspace_map START (company_id: {company_id}) ---")
    ws_id_to_info: Dict[str, Dict[str, Any]] = {}

    graphql_headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "*/*",
        "ApolloGraphql-Client-Name": "triton-script",
        "x-company-id": str(company_id),
    }
    graphql_body = {
        "query": """
        query GetWorkspace {
            viewer {
                company {
                    workspaces {
                        id
                        _id
                        name
                        description
                        created
                        modified
                    }
                }
            }
        }
        """
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                "https://mw-graph.meltwater.io/graphql",
                json=graphql_body,
                headers=graphql_headers,
            )
            if resp.status_code == 200:
                payload = resp.json()
                ws_list = (
                    payload.get("data", {})
                    .get("viewer", {})
                    .get("company", {})
                    .get("workspaces", [])
                    or []
                )
                for ws in ws_list:
                    wid = ws.get("_id")
                    if wid:
                        ws_id_to_info[str(wid)] = {
                            "id": str(wid),
                            "name": ws.get("name", "Unknown Workspace"),
                            "description": ws.get("description", "") or "",
                            "created": ws.get("created", "") or "",
                            "modified": ws.get("modified", "") or "",
                        }
                logger.info(
                    f"get_workspace_map: fetched {len(ws_id_to_info)} workspaces for company {company_id}"
                )
            else:
                logger.warning(
                    f"get_workspace_map: Failed to fetch workspaces list: HTTP {resp.status_code}"
                )
    except Exception as exc:
        logger.error(f"get_workspace_map: Error fetching workspaces: {exc}")

    if cache_key not in WORKSPACE_CACHE:
        WORKSPACE_CACHE[cache_key] = {"timestamp": now}
    WORKSPACE_CACHE[cache_key].update(
        {
            "workspaces": ws_id_to_info,
            "timestamp": time.time(),
            "company_id": company_id,
        }
    )

    return ws_id_to_info


async def get_workspace_searchdata_map(
    token: str, company_id: Optional[str] = None
) -> Dict[str, Dict[str, str]]:
    """
    Builds a searchId -> {workspaceId, workspaceName} map using the
    discovery-next GraphQL endpoint. Queries GetWorkspace first, then calls
    GetWorkspaceSearches per workspace to learn which searches belong where.
    """
    import jwt

    if not company_id:
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            company_id = decoded.get("company", {}).get("_id") or decoded.get("user", {}).get("activeCompanyId")
        except Exception:
            company_id = None

    if not company_id:
        logger.warning("get_workspace_searchdata_map: no company_id available")
        return {}

    cache_key = f"{get_cache_key(token, company_id)}_ws_search_map"
    now = time.time()
    if cache_key in WORKSPACE_CACHE:
        cached = WORKSPACE_CACHE[cache_key]
        if now - cached.get("timestamp", 0) < WORKSPACE_CACHE_TTL:
            return cached.get("search_map", {})

    logger.info(f"--- get_workspace_searchdata_map START (company_id: {company_id}) ---")
    search_id_to_ws: Dict[str, Dict[str, str]] = {}

    q_get_workspace = """
    query GetWorkspace {
        viewer {
            company {
                workspaces {
                    _id
                    name
                }
            }
        }
    }
    """

    ws_headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "*/*",
        "ApolloGraphql-Client-Name": "account",
        "x-company-id": str(company_id),
    }

    q_get_searches = """
    query GetWorkspaceSearches($companyId: ID!, $input: WorkspaceFilter) {
        company(companyId: $companyId) {
            workspaces(input: $input) {
                searches {
                    id
                    name
                }
            }
        }
    }
    """

    search_headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
        "Origin": "https://app.meltwater.com",
        "Referer": "https://app.meltwater.com/",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
        "ApolloGraphql-Client-Name": "mi-web-app",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "cross-site",
        "x-company-id": str(company_id),
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            ws_resp = await client.post(
                "https://mw-graph.meltwater.io/graphql",
                json={"query": q_get_workspace, "variables": {}},
                headers=ws_headers,
            )
            if ws_resp.status_code != 200:
                body = ""
                try:
                    body = ws_resp.text[:500]
                except Exception:
                    pass
                logger.warning(f"get_workspace_searchdata_map: GetWorkspace failed HTTP {ws_resp.status_code} body={body}")
                return search_id_to_ws

            ws_payload = ws_resp.json()
            ws_list = (
                ws_payload.get("data", {})
                .get("viewer", {})
                .get("company", {})
                .get("workspaces", [])
                or []
            )
            if not ws_list:
                logger.warning(
                    f"get_workspace_searchdata_map: no workspaces returned. Payload keys: {list(ws_payload.keys()) if isinstance(ws_payload, dict) else type(ws_payload).__name__}, errors: {ws_payload.get('errors') if isinstance(ws_payload, dict) else 'n/a'}"
                )
                return search_id_to_ws

            for ws in ws_list:
                ws_id = ws.get("_id")
                ws_name = ws.get("name")
                if not ws_id or not ws_name:
                    continue

                search_resp = await client.post(
                    "https://mw-graph.meltwater.io/graphql",
                    json={
                        "query": q_get_searches,
                        "variables": {
                            "companyId": company_id,
                            "input": {"workspaceId": ws_id},
                        },
                    },
                    headers=ws_headers,
                    timeout=120.0,
                )
                if search_resp.status_code != 200:
                    body = ""
                    try:
                        body = search_resp.text[:500]
                    except Exception:
                        pass
                    logger.warning(f"get_workspace_searchdata_map: GetWorkspaceSearches failed for {ws_id} HTTP {search_resp.status_code} body={body}")
                    continue

                search_payload = search_resp.json()
                workspaces_block = (
                    search_payload.get("data", {})
                    .get("company", {})
                    .get("workspaces", [])
                    or []
                )
                matched = 0
                for ws_block in workspaces_block:
                    for s in ws_block.get("searches", []) or []:
                        sid = s.get("id")
                        if sid is None:
                            continue
                        search_id_to_ws[str(sid)] = {
                            "workspaceId": str(ws_id),
                            "workspaceName": ws_name,
                        }
                        matched += 1
                logger.debug(f"get_workspace_searchdata_map: workspace={ws_name} matched={matched}")

            logger.info(
                f"get_workspace_searchdata_map: built map of {len(search_id_to_ws)} searches across {len(ws_list)} workspaces"
            )
    except Exception as exc:
        logger.error(f"get_workspace_searchdata_map: {exc}")

    if cache_key not in WORKSPACE_CACHE:
        WORKSPACE_CACHE[cache_key] = {"timestamp": now}
    WORKSPACE_CACHE[cache_key].update(
        {
            "search_map": search_id_to_ws,
            "timestamp": time.time(),
            "company_id": company_id,
        }
    )

    return search_id_to_ws


async def get_current_company_info(token: str) -> Optional[Dict[str, str]]:
    """Fetches current company info from Identity API using token and cross-references with company list"""
    try:
        import jwt
        import httpx

        # Decode token to get userId and current companyId
        decoded_token = jwt.decode(token, options={"verify_signature": False})
        user_id = decoded_token.get("user", {}).get("_id")
        current_company_id = decoded_token.get("company", {}).get("_id")

        if not user_id or not current_company_id:
            logger.warning("Missing userId or companyId in token")
            return None

        logger.info(
            f"--- get_current_company_info START (user: {user_id}, company: {current_company_id}) ---"
        )

        # Call Identity API to get user's companies
        identity_url = f"https://v1.identity.meltwater.io/users/{user_id}/companies?synchronizeOpportunities=true"

        async with httpx.AsyncClient(timeout=30.0) as client:
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "X-Client-Name": "mi-web-app",
            }

            resp = await client.get(identity_url, headers=headers)

            if resp.status_code != 200:
                logger.warning(f"Identity companies API failed: {resp.status_code}")
                return None

            companies = resp.json()

            # Find the current company by matching companyId
            # API response structure: [{"company": {"_id": "...", "name": "..."}, "companyMembership": {...}}]
            for company_entry in companies:
                company_obj = company_entry.get("company", {})
                if str(company_obj.get("_id")) == str(current_company_id):
                    logger.info(f"Found current company: {company_obj.get('name')}")
                    return {
                        "id": current_company_id,
                        "name": company_obj.get("name", "Unknown Company"),
                        "country": company_obj.get("country", ""),
                        "created": company_obj.get("created", ""),
                        "modified": company_obj.get("modified", ""),
                    }

            logger.warning(
                f"Current company {current_company_id} not found in user's companies list"
            )
            return None

    except Exception as e:
        logger.error(f"get_current_company_info failed: {e}")
        return None


@router.post("/warmup")
async def warmup_mappings(payload: Dict[str, str] = Body(...)):
    """Pre-fetches user and search maps to verify token and warm up caches"""
    token = payload.get("token")
    company_id = payload.get("companyId")  # Explicit company context from frontend

    if not token:
        return {"error": True, "message": "Token required"}

    try:
        # We run these to verify the token works and give the user immediate feedback
        logger.info(f"Starting warmup for company {company_id or 'token default'}...")
        user_map_task = get_user_map(token, company_id=company_id)
        search_map_task = get_search_map(token, company_id=company_id)
        company_info_task = get_current_company_info(token)

        # Use timeout to prevent hanging on large user lists - 60 seconds max for entire warmup
        user_map_result, search_map, company_info = await asyncio.wait_for(
            asyncio.gather(
                user_map_task,
                search_map_task,
                company_info_task,
                return_exceptions=True,
            ),
            timeout=60.0,
        )

        # Check for exceptions in results
        if isinstance(user_map_result, Exception):
            raise user_map_result
        if isinstance(search_map, Exception):
            logger.warning(f"Search map fetch failed: {search_map}")
            search_map = {}
        if isinstance(company_info, Exception):
            logger.warning(f"Company info fetch failed: {company_info}")
            company_info = None

        user_map, unique_count = user_map_result

        # Extract plain lists for the modal
        users_list = []
        seen_emails = set()
        for v in user_map.values():
            if isinstance(v, dict) and "email" in v and v["email"] not in seen_emails:
                users_list.append(v)
                seen_emails.add(v["email"])

        searches_list = [{"id": k, "name": v} for k, v in search_map.items()]

        return {
            "success": True,
            "meta": {
                "usersFound": unique_count,
                "searchesFound": len(search_map),
                "userList": users_list,
                "searchList": searches_list,
                "currentCompany": company_info,
            },
        }
    except asyncio.TimeoutError:
        logger.error(
            "Warmup failed: Operation timed out after 60 seconds. User list may be too large."
        )
        return {
            "error": True,
            "message": "Warmup timed out after 60 seconds. The user list is very large - enrichment will still work but may be slower.",
        }
    except Exception as e:
        error_msg = str(e) if str(e) else f"{type(e).__name__}: {repr(e)}"
        logger.error(f"Warmup failed: {error_msg}")
        logger.exception("Full warmup exception details:")
        return {"error": True, "message": error_msg}


def deep_enrich(obj: Any, user_map: Dict, search_map: Dict) -> Any:
    """Recursively enriches a JSON object with user and search names"""
    if isinstance(obj, list):
        return [deep_enrich(item, user_map, search_map) for item in obj]
    if not isinstance(obj, dict):
        return obj

    new_obj = {}
    for k, v in obj.items():
        new_obj[k] = v
        # User mapping - try to enrich common ID fields
        # Standard field names
        if k in [
            "userId",
            "updatedBy",
            "createdBy",
            "modifiedBy",
            "ownerId",
            "addedBy",
            "author",
        ] and isinstance(v, (str, int)):
            info = user_map.get(str(v))
            if info:
                new_obj[f"{k}_Name"] = info["name"]
                new_obj[f"{k}_Email"] = info["email"]

        # Alternative field name patterns (e.g., createdById, updatedByUserId)
        if k in [
            "createdById",
            "updatedById",
            "modifiedById",
            "ownerUserId",
            "userIdStr",
        ] and isinstance(v, (str, int)):
            # Map to standard base name for the enriched fields
            base_name = k.replace("Id", "").replace("Str", "").replace("User", "")
            if base_name.endswith("By"):
                base_name = base_name  # createdBy, updatedBy, modifiedBy
            elif base_name == "owner":
                base_name = "owner"
            info = user_map.get(str(v))
            if info:
                new_obj[f"{base_name}_Name"] = info["name"]
                new_obj[f"{base_name}_Email"] = info["email"]

        # Handle camelCase variations like lastModifiedBy
        if k in ["lastModifiedBy", "lastUpdatedBy"] and isinstance(v, (str, int)):
            info = user_map.get(str(v))
            if info:
                new_obj["updatedBy_Name"] = info["name"]
                new_obj["updatedBy_Email"] = info["email"]

        # Search mapping
        if k in ["searchId", "savedSearchId", "id"] and isinstance(v, (str, int)):
            sid = str(v)
            if sid in search_map:
                new_obj[f"{k}_Name"] = search_map[sid]

        # Recurse if value is dict or list
        if isinstance(v, (dict, list)):
            new_obj[k] = deep_enrich(v, user_map, search_map)

    return new_obj


def ensure_enrichment_fields(data: list) -> list:
    """
    Ensures all enrichment fields (_Name, _Email) are present in all items.
    Also ensures _Name and _Email appear right after their base field for proper ordering.
    """
    if not data:
        return data
    
    # Define base fields that should have enrichment (user ID fields)
    base_fields = ["createdBy", "updatedBy", "userId", "author", "owner", "modifiedBy", "addedBy"]
    
    # First pass: detect which base fields exist in the data
    base_fields_present = set()
    for item in data:
        for key in item.keys():
            if key in base_fields:
                base_fields_present.add(key)
    
    # Build required fields: for each base field, ensure {base}_Name and {base}_Email exist
    required_fields = set()
    for base in base_fields_present:
        required_fields.add(f"{base}_Name")
        required_fields.add(f"{base}_Email")
    
    # Also collect any existing enrichment fields from the data
    for item in data:
        for key in item.keys():
            if key.endswith("_Name") or key.endswith("_Email"):
                required_fields.add(key)
    
    if not required_fields:
        return data
    
    # Rebuild each item with correct field order
    for i, item in enumerate(data):
        new_item = {}
        for key, value in item.items():
            new_item[key] = value
            # After a base field, insert its _Name and _Email if not already present
            if key in base_fields_present:
                name_field = f"{key}_Name"
                email_field = f"{key}_Email"
                # Add if required but missing from original item
                if name_field in required_fields and name_field not in item:
                    new_item[name_field] = ""
                if email_field in required_fields and email_field not in item:
                    new_item[email_field] = ""
        # Add any remaining enrichment fields that weren't added
        for field in required_fields:
            if field not in new_item:
                new_item[field] = ""
        data[i] = new_item
    
    return data


def convert_timestamps(data: list) -> list:
    """
    Converts epoch timestamps (milliseconds) to human-readable ISO 8601 format.
    Auto-detects timestamp fields by name (ends with 'At', 'Date', etc.)
    """
    if not data:
        return data
    
    from datetime import datetime
    
    for item in data:
        for key, value in list(item.items()):
            # Check if this field is a timestamp
            if key.endswith("At") or key.endswith("Date"):
                if isinstance(value, (int, float)) and value > 0:
                    try:
                        # Handle milliseconds (13 digits) vs seconds (10 digits)
                        if value > 9999999999:  # Milliseconds
                            dt = datetime.fromtimestamp(value / 1000)
                        else:  # Seconds
                            dt = datetime.fromtimestamp(value)
                        item[key] = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                    except (ValueError, OSError, OverflowError):
                        pass  # Keep original if conversion fails
    return data


async def list_users_identity_handler(
    token: str, company_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Fetches all users for a company using the Identity REST API.
    Faster and more reliable for cross-company mapping than GraphQL.
    """
    logger.info(f"=== LIST USERS IDENTITY REST START ({company_id}) ===")

    try:
        import jwt

        if not company_id:
            try:
                decoded_token = jwt.decode(token, options={"verify_signature": False})
                company_id = decoded_token.get("company", {}).get(
                    "_id"
                ) or decoded_token.get("user", {}).get("activeCompanyId")
            except:
                pass

        if not company_id:
            return {"error": True, "message": "Company ID required"}

        # Use proxy URL as primary to avoid DNS and certificate issues
        url = f"https://app.meltwater.com/api/identity/v1/companies/{company_id}/users"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "X-Client-Name": "mi-web-app",
            "x-company-id": str(company_id),
            "x-account-id": str(company_id),
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                # 3s timeout for proxy - if it's slow, it's likely not working
                resp = await client.get(url, headers=headers, timeout=3.0)
                if resp.status_code != 200:
                    # Fallback to direct URL if proxy fails
                    direct_url = f"https://v1.identity.meltwater.io/companies/{company_id}/users"
                    resp = await client.get(direct_url, headers=headers, timeout=2.0)
            except Exception as e:
                logger.warning(
                    f"Primary Identity fetch failed: {e}, trying direct fallback..."
                )
                direct_url = (
                    f"https://v1.identity.meltwater.io/companies/{company_id}/users"
                )
                try:
                    resp = await client.get(direct_url, headers=headers, timeout=2.0)
                except Exception as e2:
                    logger.error(f"Identity direct fallback also failed: {e2}")
                    return {"error": True, "message": "Identity REST failed"}

            if resp.status_code != 200:
                logger.error(f"Identity API failed: {resp.status_code}")
                return {
                    "error": True,
                    "status": resp.status_code,
                    "message": "Identity API failed",
                }

            raw_data = resp.json()
            users_list = []
            if isinstance(raw_data, list):
                users_list = raw_data
            elif isinstance(raw_data, dict):
                users_list = raw_data.get("users") or raw_data.get("data") or [raw_data]

            normalized = []
            for u in users_list:
                if isinstance(u, dict):
                    inner = u.get("user", u)
                    if not isinstance(inner, dict):
                        logger.warning(f"Identity user 'user' field is not a dict, keys={list(u.keys())}")
                        inner = u
                    uid = (
                        inner.get("id")
                        or inner.get("_id")
                        or inner.get("userId")
                        or inner.get("user_id")
                        or inner.get("accountId")
                    )
                    if not uid:
                        logger.warning(f"Identity user missing ID field, nested keys={list(inner.keys())}, outer keys={list(u.keys())}")
                    normalized.append(
                        {
                            "_id": uid,
                            "membershipId": inner.get("membershipId") or (u.get("companyMembership") or {}).get("_id"),
                            "firstName": inner.get("firstName") or inner.get("givenName") or "",
                            "lastName": inner.get("lastName") or inner.get("familyName") or inner.get("surname") or "",
                            "email": inner.get("email") or inner.get("mail") or "",
                        }
                    )

            return {"data": normalized}

    except Exception as e:
        logger.error(f"Identity REST request failed: {e}")
        return {"error": True, "message": str(e)}


# --- END HELPERS ---


async def get_user_role_map(token: str, company_id: str) -> Dict[str, str]:
    """
    Fetches all roles for a company and builds a userId -> roleName mapping.
    Uses CompanyRolesGet GraphQL query to get roles with their associatedPermissions.
    """
    logger.info(f"=== GET USER ROLE MAP START (companyId: {company_id}) ===")

    user_role_map = {}

    try:
        headers = {
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
            "Origin": "https://app.meltwater.com",
            "Referer": "https://app.meltwater.com/",
            "Authorization": f"Bearer {token}",
            "content-type": "application/json",
            "apollographql-client-name": "account",
            "x-company-id": str(company_id),
        }

        graphql_query = """query CompanyRolesGet($companyId: ID!, $filters: RolesFilter) {
          companyRolesGet(companyId: $companyId, filters: $filters) {
            _id
            name
            description
            modified
            modifiedBy
            permissions {
              account
              analyze
              dashboards
              downloads
              engage
              explore
              explorePlus
              genAiLens
              manageUsers
              mediaRelations
              meltwaterApi
              miraStudio
              report
              share
              __typename
            }
            associatedPermissions {
              userId
              permissionId
              __typename
            }
            __typename
          }
        }"""

        body = {
            "operationName": "CompanyRolesGet",
            "variables": {"companyId": company_id},
            "query": graphql_query,
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                url="https://mw-graph.meltwater.io/graphql",
                json=body,
                headers=headers,
                timeout=30.0,
            )

            if response.status_code >= 400:
                logger.error(f"Roles request failed: {response.status_code}")
                return {}

            response_data = response.json()

            if "errors" in response_data:
                logger.error(f"GraphQL errors in roles: {response_data['errors']}")
                return {}

            roles = response_data.get("data", {}).get("companyRolesGet", [])
            logger.info(f"Found {len(roles)} roles")

            for role in roles:
                role_id = role.get("_id")
                role_name = role.get("name", "Unknown Role")
                associated_perms = role.get("associatedPermissions", []) or []

                for perm in associated_perms:
                    user_id = perm.get("userId")
                    if user_id:
                        user_role_map[str(user_id)] = role_name

            logger.info(f"Mapped {len(user_role_map)} users to roles")

    except Exception as e:
        logger.error(f"Failed to get user role map: {e}")

    return user_role_map


async def list_users_complete_handler(
    token: str, company_id: Optional[str] = None, max_pages: int = 50
) -> Dict[str, Any]:
    """
    Composite handler that fetches all users with complete details using GraphQL with automatic pagination.
    Recursively fetches all pages until all users are retrieved.
    Also fetches roles and maps them to each user.

    Args:
        token: Authorization token
        company_id: Company ID to fetch users for
        max_pages: Maximum number of pages to fetch (default 50 = 5000 users) to prevent runaway pagination
    """
    logger.info("=== LIST USERS COMPLETE COMPOSITE HANDLER START ===")

    try:
        # Extract companyId from token if not provided
        import jwt  # PyJWT is installed as 'jwt' module

        if not token:
            return {
                "error": True,
                "status": 400,
                "message": "Token is required for this composite request",
                "data": None,
            }

        if not company_id:
            try:
                # Decode JWT token to get companyId
                decoded_token = jwt.decode(token, options={"verify_signature": False})
                company_id = decoded_token.get("company", {}).get("_id")

                if not company_id:
                    # Try alternative path
                    company_id = decoded_token.get("user", {}).get("activeCompanyId")

                if not company_id:
                    return {
                        "error": True,
                        "status": 400,
                        "message": "Could not extract companyId from token",
                        "data": None,
                    }
            except Exception as e:
                logger.error(f"Failed to decode token: {e}")
                return {
                    "error": True,
                    "status": 400,
                    "message": f"Failed to decode token: {str(e)}",
                    "data": None,
                }

        logger.info(f"Fetching users for companyId: {company_id}")

        all_users = []
        page = 1
        page_size = 100
        has_next_page = True

        headers = {
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
            "Origin": "https://app.meltwater.com",
            "Referer": "https://app.meltwater.com/",
            "Authorization": f"Bearer {token}",
            "content-type": "application/json",
            "apollographql-client-name": "account",
            "x-company-id": str(company_id),
            "x-account-id": str(company_id),
        }

        graphql_query = """query CompanyUsersConnection($companyId: ID!, $paginationRule: PaginationRule, $sortRule: UsersSortRule, $filters: UserFilter) {
          companyUsersConnection(
            companyId: $companyId
            paginationRule: $paginationRule
            sortRule: $sortRule
            filters: $filters
          ) {
            _id
            totalCount
            edges {
              node {
                activeWorkspaceId
                lastActiveDate
                isOnAdminWorkspace
                addedByHaakon
                platforms
                userSeatId
                user {
                  _id
                  firstName
                  lastName
                  email
                  pending
                  timezone
                  language
                  created
                  modified
                  isExternalIdpUser
                  isInternal
                  userGroups {
                    _id
                    name
                    __typename
                  }
                  appPermissions(companyId: $companyId) {
                    roleId
                    account
                    analyze
                    dashboards
                    downloads
                    engage
                    explore
                    explorePlus
                    genAiLens
                    manageUsers
                    mediaRelations
                    meltwaterApi
                    miraStudio
                    report
                    share
                    dashboards
                    workspaces {
                      workspaceId
                      roleId
                      overrides {
                        account
                        analyze
                        dashboards
                        downloads
                        engage
                        explore
                        explorePlus
                        genAiLens
                        manageUsers
                        mediaRelations
                        meltwaterApi
                        miraStudio
                        report
                        share
                        dashboards
                        __typename
                      }
                      __typename
                    }
                    __typename
                  }
                  workspaces(companyId: $companyId) {
                    _id
                    name
                    __typename
                  }
                  __typename
                }
                __typename
              }
              __typename
            }
            pageInfo {
              hasNextPage
              hasPreviousPage
              page
              pageSize
              __typename
            }
            __typename
          }
        }"""

        async def fetch_all_pages() -> list:
            """Fetch all users for a company without filtering by isInternal, then classify in Python"""
            all_pages_users = []
            page = 1
            has_next_page = True

            while has_next_page and page <= max_pages:
                body = {
                    "operationName": "CompanyUsersConnection",
                    "variables": {
                        "companyId": company_id,
                        "paginationRule": {"page": page, "pageSize": page_size},
                        "sortRule": {"direction": "ASC", "field": "NAME"},
                    },
                    "query": graphql_query,
                }

                response = await client.post(
                    url="https://mw-graph.meltwater.io/graphql",
                    json=body,
                    headers=headers,
                    timeout=30.0,
                )

                if response.status_code >= 400:
                    logger.error(
                        f"GraphQL request failed for page {page}: {response.status_code}"
                    )
                    break

                response_data = response.json()

                if "errors" in response_data:
                    logger.error(
                        f"GraphQL errors on page {page}: {response_data['errors']}"
                    )
                    break

                company_users_connection = response_data.get("data", {}).get(
                    "companyUsersConnection", {}
                )
                edges = company_users_connection.get("edges", [])
                page_info = company_users_connection.get("pageInfo", {})

                users_on_page = []
                for edge in edges:
                    node = edge.get("node", {})
                    user = node.get("user", {})
                    if user:
                        user["membershipId"] = node.get("_id")
                        users_on_page.append(user)

                logger.info(f"Found {len(users_on_page)} users on page {page}")
                all_pages_users.extend(users_on_page)

                has_next_page = page_info.get("hasNextPage", False)
                page += 1

                if page > max_pages:
                    logger.warning(
                        f"Reached max_pages limit ({max_pages}). Fetched {len(all_pages_users)} users."
                    )
                    break

            return all_pages_users

        async with httpx.AsyncClient(timeout=30.0) as client:
            all_users = await fetch_all_pages()
            logger.info(f"Successfully fetched {len(all_users)} users in total")

            user_role_map = await get_user_role_map(token, company_id)

            for user in all_users:
                user_id = user.get("_id")
                if user_id and user_id in user_role_map:
                    user["role"] = user_role_map[user_id]

            return {
                "data": all_users,
                "meta": {"totalCount": len(all_users), "companyId": company_id},
            }

    except Exception as e:
        logger.error(f"List users complete request failed: {e}")
        logger.exception("Full exception details:")
        return {
            "error": True,
            "status": 500,
            "message": f"List users complete request failed: {str(e)}",
            "data": None,
        }


async def search_usage_handler(
    token: str, placeholders: Dict[str, str]
) -> Dict[str, Any]:
    """
    Composite handler that fetches all searches with full details and their usage information.
    First gets the list of searches from the new endpoint, then gets usage for each search, and merges the results.
    """
    logger.info("=== SEARCH USAGE COMPOSITE HANDLER START ===")

    user_map = {}  # Initialize for enrichment

    try:
        # Extract companyId from token for the first request
        import jwt  # PyJWT is installed as 'jwt' module

        if not token:
            return {
                "error": True,
                "status": 400,
                "message": "Token is required for this composite request",
                "data": None,
            }

        try:
            # Decode JWT token to get companyId
            decoded_token = jwt.decode(token, options={"verify_signature": False})
            company_id = decoded_token.get("company", {}).get("_id")

            if not company_id:
                # Try alternative path
                company_id = decoded_token.get("user", {}).get("activeCompanyId")

            if not company_id:
                return {
                    "error": True,
                    "status": 400,
                    "message": "Could not extract companyId from token",
                    "data": None,
                }
        except Exception as e:
            logger.error(f"Failed to decode token: {e}")
            return {
                "error": True,
                "status": 400,
                "message": f"Failed to decode token: {str(e)}",
                "data": None,
            }

        # Fetch user map for enrichment (parallel with search requests)
        logger.info(f"Fetching user map for company {company_id}...")
        try:
            user_map_task = get_user_map(token, company_id=company_id)
            workspace_map_task = get_workspace_searchdata_map(token, company_id=company_id)
        except Exception as e:
            logger.warning(f"Could not start user map fetch: {e}")
            user_map_task = None
            workspace_map_task = None

        # First request: Get all searches with full details (with pagination for large datasets)
        searches_url = (
            f"https://masfsearch.meltwater.io/masfsearch/v2/search/list/{company_id}"
        )
        searches_headers = {
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
            "Origin": "https://app.meltwater.com",
            "Referer": "https://app.meltwater.com/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "cross-site",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
            "X-Client-Name": "mi-web-app",
            "Authorization": f"Bearer {token}",
            "sec-ch-ua": '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"macOS"',
        }

        # Fetch searches - API returns all results ignoring limit/offset, so fetch once
        all_searches = []
        page_size = 500

        async with httpx.AsyncClient(timeout=300.0) as client:
            logger.info(f"Fetching searches (requesting max {page_size})...")

            try:
                resp = await client.get(
                    url=searches_url,
                    headers=searches_headers,
                    params={"limit": page_size},
                    timeout=300.0,
                )

                if resp.status_code >= 400:
                    logger.error(f"Searches request failed: {resp.status_code}")
                    return {
                        "error": True,
                        "status": resp.status_code,
                        "message": "Failed to fetch searches",
                        "data": None,
                    }

                searches_data = resp.json()

                # Handle response format - extract searches list
                if isinstance(searches_data, dict):
                    page_searches = (
                        searches_data.get("searches") or searches_data.get("data") or []
                    )
                    # Check for totalCount in response for pagination
                    total_count = searches_data.get("totalCount") or searches_data.get(
                        "total"
                    )
                    if total_count:
                        logger.info(f"API reports totalCount: {total_count}")
                else:
                    page_searches = (
                        searches_data if isinstance(searches_data, list) else []
                    )
                    total_count = len(page_searches)

                if not page_searches:
                    logger.warning("No searches returned from API")
                    return {
                        "data": {
                            "searches": [],
                            "usage": {},
                            "summary": {
                                "totalSearches": 0,
                                "searchesWithUsage": 0,
                                "searchesWithoutUsage": 0,
                            },
                        }
                    }

                all_searches.extend(page_searches)
                logger.info(
                    f"Fetched {len(all_searches)} searches (API ignores pagination params, returning all at once)"
                )

            except httpx.TimeoutException:
                logger.error("Timeout fetching searches")
                return {
                    "error": True,
                    "status": 408,
                    "message": "Timeout fetching searches",
                    "data": None,
                }
            except Exception as e:
                logger.error(f"Error fetching searches: {e}")
                return {
                    "error": True,
                    "status": 500,
                    "message": f"Error fetching searches: {str(e)}",
                    "data": None,
                }

            searches = all_searches
            logger.info(f"Found {len(searches)} searches total")

            # Await user map if task was started
            if user_map_task:
                try:
                    user_map_result = await user_map_task
                    if isinstance(user_map_result, tuple):
                        user_map, _ = user_map_result
                    else:
                        user_map = {}
                    logger.info(f"User map fetched: {len(user_map)} users")
                except Exception as e:
                    logger.warning(f"Failed to get user map: {e}")
                    user_map = {}

            if not searches:
                return {
                    "data": {
                        "searches": [],
                        "usage": {},
                        "summary": {
                            "totalSearches": 0,
                            "searchesWithUsage": 0,
                            "searchesWithoutUsage": 0,
                        },
                    }
                }

            # Extract search IDs from the new endpoint format (normalize to avoid duplicates and ensure string type)
            search_ids = []
            seen_ids = set()
            for search in searches:
                # Try both possible ID field names for robustness
                search_id = search.get("savedSearchId") or search.get("id")
                if search_id:
                    # Convert to string for consistent matching
                    search_id_str = str(search_id)
                    if search_id_str not in seen_ids:
                        seen_ids.add(search_id_str)
                        search_ids.append(search_id_str)

            logger.info(
                f"Extracted {len(search_ids)} unique search IDs for usage lookup"
            )

            if not search_ids:
                return {
                    "data": {
                        "searches": searches,
                        "usage": {},
                        "summary": {
                            "totalSearches": len(searches),
                            "searchesWithUsage": 0,
                            "searchesWithoutUsage": len(searches),
                        },
                    }
                }

            # Second request: Get usage for all searches
            usage_url = (
                "https://discovery-next-mw-apollo-production.meltwater.io/graphql"
            )
            usage_headers = {
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
                "Origin": "https://app.meltwater.com",
                "Referer": "https://app.meltwater.com/",
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
                "apollographql-client-name": "discovery-next",
                "apollographql-client-version": "0.0.0",
                "sec-ch-ua": '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"macOS"',
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "cross-site",
            }

            # Split search_ids into chunks of 50 to avoid 504 Gateway Time-out
            chunk_size = 50
            search_id_chunks = [search_ids[i:i + chunk_size] for i in range(0, len(search_ids), chunk_size)]
            usages = []
            
            logger.info(f"Fetching search usages in {len(search_id_chunks)} chunks of max {chunk_size} IDs...")
            
            try:
                for idx, chunk in enumerate(search_id_chunks):
                    logger.info(f"Fetching usage chunk {idx+1}/{len(search_id_chunks)} ({len(chunk)} IDs)...")
                    usage_body = {
                        "operationName": "searchUsagesByIds",
                        "variables": {"ids": chunk},
                        "query": """query searchUsagesByIds($ids: [ID!]) {
  searchUsagesByIds(ids: $ids) {
    id
    usages {
      alerts { id name __typename }
      combinations { id name __typename }
      dashboards { id name url type __typename }
      digests { id name __typename }
      monitors { id name __typename }
      __typename
    }
    __typename
  }
}""",
                    }

                    usage_response = await client.post(
                        url=usage_url, json=usage_body, headers=usage_headers, timeout=120.0
                    )

                    if usage_response.status_code >= 400:
                        logger.error(f"Usage chunk {idx+1} failed: {usage_response.status_code}")
                        return {
                            "error": True,
                            "status": usage_response.status_code,
                            "message": f"Failed to fetch search usages chunk {idx+1}",
                            "data": None,
                        }

                    usage_data = usage_response.json()

                    if "errors" in usage_data:
                        logger.error(f"GraphQL errors in usage chunk {idx+1}: {usage_data['errors']}")
                        return {
                            "error": True,
                            "status": 400,
                            "message": f"GraphQL errors in usage request chunk {idx+1}",
                            "data": usage_data,
                        }

                    chunk_usages = usage_data.get("data", {}).get("searchUsagesByIds", [])
                    usages.extend(chunk_usages)
            except Exception as e:
                logger.error(f"Failed during usage chunking: {e}")
                return {
                    "error": True,
                    "status": 500,
                    "message": f"Failed during usage fetch: {str(e)}",
                    "data": None,
                }

            # Create a mapping of search ID to usage (convert to strings for type consistency)
            usage_map = {}
            for usage_item in usages:
                # The usage endpoint returns ID as "id" field
                usage_id = usage_item.get("id")
                if usage_id:
                    usage_map[str(usage_id)] = usage_item["usages"]

            # Fetch newsletters to get search usage (List NL 2.0 endpoint)
            newsletter_url = (
                "https://nl-api.newsletters.meltwater.io/company/newsletters"
            )
            newsletter_headers = {
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.9",
                "Origin": "https://app.meltwater.com",
                "Priority": "u=1, i",
                "Referer": "https://app.meltwater.com/",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "cross-site",
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
                "Authorization": f"Bearer {token}",
            }

            newsletter_search_map: Dict[str, List[Dict[str, Any]]] = {}
            try:
                logger.info("Fetching newsletters for search usage...")
                nl_response = await client.get(
                    url=newsletter_url,
                    headers=newsletter_headers,
                    timeout=300.0,
                )

                if nl_response.status_code >= 400:
                    logger.warning(
                        f"Newsletter request failed: {nl_response.status_code}"
                    )
                else:
                    newsletters_data = nl_response.json()
                    newsletters_list = (
                        newsletters_data
                        if isinstance(newsletters_data, list)
                        else newsletters_data.get("data", [])
                    )

                    for newsletter in newsletters_list:
                        newsletter_id = newsletter.get("_id")
                        newsletter_name = newsletter.get("name", "Unnamed Newsletter")

                        for section in newsletter.get("sections", []):
                            for input_item in section.get("inputs", []):
                                if input_item.get("type") == "savedSearch":
                                    search_id = input_item.get("id")
                                    if search_id:
                                        search_id_str = str(search_id)
                                        if search_id_str not in newsletter_search_map:
                                            newsletter_search_map[search_id_str] = []
                                        newsletter_search_map[search_id_str].append(
                                            {
                                                "id": newsletter_id,
                                                "name": newsletter_name,
                                                "__typename": "newsletter",
                                            }
                                        )

                    logger.info(
                        f"Found {len(newsletter_search_map)} searches used in newsletters"
                    )

            except Exception as e:
                logger.warning(f"Failed to fetch newsletters: {e}")

            # Merge newsletter usage into usage_map
            for search_id, nl_items in newsletter_search_map.items():
                if search_id in usage_map:
                    usage_map[search_id]["newsletters"] = nl_items
                else:
                    usage_map[search_id] = {"newsletters": nl_items}

            # Merge searches with their usage data (handle duplicates by ID)
            searches_with_usage = []
            searches_with_usage_count = 0
            processed_ids = set()

            for search in searches:
                # Handle both ID formats: savedSearchId from new endpoint or id from other endpoints
                search_id = search.get("savedSearchId") or search.get("id")

                if not search_id:
                    logger.warning(
                        f"Search missing both savedSearchId and id: {search}"
                    )
                    continue

                # Convert to string for consistent matching
                search_id_str = str(search_id)

                # Skip if we already processed this search ID (avoid duplicates)
                if search_id_str in processed_ids:
                    logger.debug(f"Skipping duplicate search ID: {search_id_str}")
                    continue

                processed_ids.add(search_id_str)

                # Create a copy with consistent ID field
                search_with_usage = search.copy()
                search_with_usage["id"] = (
                    search_id_str  # Ensure consistent ID field for frontend
                )
                search_with_usage["usage"] = usage_map.get(search_id_str, {})

                # Debug logging for mapping verification
                if search_id in usage_map:
                    logger.debug(
                        f"Found usage for search {search_id}: {len(usage_map[search_id])} categories"
                    )
                else:
                    logger.debug(f"No usage found for search {search_id}")

                # Calculate total usage count
                total_usage = 0
                usage_summary = {
                    "alerts": 0,
                    "combinations": 0,
                    "dashboards": 0,
                    "digests": 0,
                    "monitors": 0,
                    "newsletters": 0,
                }

                if search_with_usage["usage"]:
                    for category, items in search_with_usage["usage"].items():
                        if items and isinstance(items, list):
                            count = len(items)
                            usage_summary[category] = count
                            total_usage += count

                search_with_usage["usageSummary"] = usage_summary
                search_with_usage["totalUsageCount"] = total_usage
                search_with_usage["isUsed"] = total_usage > 0

                if total_usage > 0:
                    searches_with_usage_count += 1

                searches_with_usage.append(search_with_usage)

            # Sort by total usage (descending) and then by name
            searches_with_usage.sort(
                key=lambda x: (-x["totalUsageCount"], x.get("name", "").lower())
            )

            # Apply filterNames if provided
            filter_names_raw = placeholders.get("filterNames") or ""
            filter_names = []
            if filter_names_raw:
                filter_names = [name.strip() for name in filter_names_raw.split("\n") if name.strip()]
                
            if filter_names:
                filtered_searches = []
                filter_names_lower = [name.lower() for name in filter_names]
                for search in searches_with_usage:
                    search_name = search.get("name", "")
                    if search_name and search_name.lower() in filter_names_lower:
                        filtered_searches.append(search)
                logger.info(f"Filtered {len(searches_with_usage)} searches down to {len(filtered_searches)}")
                searches_with_usage = filtered_searches

            # Enrich final results with user data
            if user_map:
                logger.info(
                    f"Enriching {len(searches_with_usage)} searches_with_usage with user_map"
                )
                searches_with_usage = [
                    deep_enrich(item, user_map, {}) for item in searches_with_usage
                ]
                searches_with_usage = ensure_enrichment_fields(searches_with_usage)
                searches_with_usage = convert_timestamps(searches_with_usage)

            workspace_map = {}
            try:
                workspace_map = await workspace_map_task
            except Exception as e:
                logger.warning(f"Failed to get workspace map: {e}")

            if workspace_map:
                matched = 0
                for search in searches_with_usage:
                    sid = str(search.get("id") or search.get("savedSearchId") or "")
                    if not sid:
                        continue
                    ws = workspace_map.get(sid)
                    if ws:
                        matched += 1
                        search["workspaceId"] = ws.get("workspaceId")
                        search["workspaceName"] = ws.get("workspaceName")
                logger.info(f"Workspace enrichment matched {matched} searches")

            for search in searches_with_usage:
                ws_id = search.get("workspaceId")
                ws_name = search.get("workspaceName")
                if ws_id is not None or ws_name is not None:
                    new_item = {}
                    for k, v in search.items():
                        new_item[k] = v
                        if k == "updatedAt":
                            new_item["workspaceId"] = ws_id
                            new_item["workspaceName"] = ws_name or "Admin Workspace"
                    search.clear()
                    search.update(new_item)
                else:
                    search.setdefault("workspaceId", None)
                    search.setdefault("workspaceName", "Admin Workspace")

            result = {
                "data": {
                    "searches": searches_with_usage,
                    "usage": usage_map,
                    "summary": {
                        "totalSearches": len(searches_with_usage),
                        "searchesWithUsage": searches_with_usage_count,
                        "searchesWithoutUsage": len(searches_with_usage)
                        - searches_with_usage_count,
                    },
                }
            }

            # Log summary for debugging
            # Log detailed debugging information about search IDs
            logger.info(f"Search objects (first 2): {searches[:2]}")
            logger.info(f"Usage objects (first 2): {usages[:2]}")
            logger.info(f"Usage map keys: {list(usage_map.keys())[:5]}")

            logger.info(
                f"Successfully processed {len(searches_with_usage)} searches with usage from new endpoint"
            )
            logger.info(f"Summary: {result['data']['summary']}")

            # Log a few examples of searches with usage for verification
            searches_with_usage_examples = [
                s for s in searches_with_usage if s.get("totalUsageCount", 0) > 0
            ][:3]
            if searches_with_usage_examples:
                logger.info(f"Sample searches with usage:")
                for example in searches_with_usage_examples:
                    logger.info(
                        f"  - Search ID: {example.get('id')}, Name: {example.get('name', 'N/A')}, Usage: {example.get('totalUsageCount', 0)}"
                    )
            else:
                logger.warning(
                    "No searches found with usage data - this may indicate a mapping issue"
                )

            return result

    except Exception as e:
        logger.error(f"Composite request failed: {e}")
        logger.exception("Full exception details:")
        return {
            "error": True,
            "status": 500,
            "message": f"Composite request failed: {str(e)}",
            "data": None,
        }



async def list_searches_handler(
    token: str, placeholders: Dict[str, str]
) -> Dict[str, Any]:
    """
    Handler for List Searches (Full) - fetches all searches in a single request.
    Note: The API doesn't support pagination (limit/offset) - it always returns all searches.
    Using a longer timeout to handle large datasets (8000+ searches).
    User data enrichment is applied to map user IDs to names and emails.

    Supports optional filtering:
    - filterNames: Filter by specific search names (one per line, case-insensitive)
    """
    logger.info("=== LIST SEARCHES HANDLER START ===")
    import asyncio

    company_id = placeholders.get("companyId") or placeholders.get("accountId")
    if not company_id:
        return {
            "error": True,
            "status": 400,
            "message": "companyId/accountId is required",
        }

    # Get optional filterNames - list of search names to filter by (one per line)
    filter_names_raw = placeholders.get("filterNames") or ""
    filter_names = []
    if filter_names_raw:
        # Split by newlines and clean up
        filter_names = [
            name.strip() for name in filter_names_raw.split("\n") if name.strip()
        ]
        logger.info(f"Filtering by {len(filter_names)} specific search names")

    try:
        # Use a longer timeout (300 seconds) to handle large datasets
        async with httpx.AsyncClient(timeout=300.0) as client:
            headers = {
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.9",
                "Connection": "keep-alive",
                "Origin": "https://app.meltwater.com",
                "Referer": "https://app.meltwater.com/",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "cross-site",
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
                "X-Client-Name": "mi-web-app",
                "Authorization": f"Bearer {token}",
                "sec-ch-ua": '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": "'macOS'",
            }

            # Pre-fetch user map and workspace searchdata map for enrichment (parallel with API calls)
            logger.info(
                f"Pre-fetching user map and workspace searchdata map for enrichment (companyId: {company_id})..."
            )
            user_map_task = get_user_map(token, company_id=company_id)
            workspace_map_task = get_workspace_searchdata_map(token, company_id=company_id)

            # Fetch all searches in a single request (no pagination support)
            search_url = f"https://masfsearch.meltwater.io/masfsearch/v2/search/list/{company_id}"

            logger.info(f"Fetching all searches for company {company_id}...")

            try:
                resp = await client.get(search_url, headers=headers, timeout=300.0)

                if resp.status_code != 200:
                    logger.error(
                        f"Search list API failed: {resp.status_code} - {resp.text[:200]}"
                    )
                    return {
                        "error": True,
                        "status": resp.status_code,
                        "message": f"API failed: {resp.text[:200]}",
                    }

                data = resp.json()

                # Handle response format - could be list or dict with searches/data fields
                if isinstance(data, dict):
                    searches = data.get("searches") or data.get("data") or []
                else:
                    searches = data if isinstance(data, list) else []

                logger.info(f"Fetched {len(searches)} searches")
                logger.info(f"[workspace] first raw keys={list(searches[0].keys()) if searches else []}")
                for probe in searches[:5]:
                    ws_candidates = {
                        "top": probe.get("workspaceId") or probe.get("workspace_id") or probe.get("workspace"),
                        "filter.searchClause.workspaceId": (probe.get("filter") or {}).get("searchClause", {}).get("workspaceId") if isinstance(probe.get("filter"), dict) else None,
                        "settings.workspaceId": (probe.get("settings") or {}).get("workspaceId") if isinstance(probe.get("settings"), dict) else None,
                        "query.workspaceId": (probe.get("query") or {}).get("workspaceId") if isinstance(probe.get("query"), dict) else None,
                    }
                    logger.info(f"[workspace] probe candidates={ws_candidates}")

                # Wait for user map and enrich results
                try:
                    user_map_result = await user_map_task
                    user_map, unique_count = user_map_result
                except Exception as e:
                    logger.warning(f"Failed to get user map: {e}")
                    user_map = {}
                    unique_count = 0

                # Enrich searches with user data
                logger.info(
                    f"Enriching {len(searches)} searches with user_map({len(user_map)}) using companyId: {company_id}"
                )
                enriched_searches = [
                    deep_enrich(item, user_map, {}) for item in searches
                ]
                # Ensure all enrichment fields are present (fix for CSV columns)
                enriched_searches = ensure_enrichment_fields(enriched_searches)
                # Convert epoch timestamps to human-readable format
                enriched_searches = convert_timestamps(enriched_searches)

                # Enrich searches with workspace data
                try:
                    workspace_map = await workspace_map_task
                except Exception as e:
                    logger.warning(f"Failed to get workspace map: {e}")
                    workspace_map = {}

                logger.info(f"[workspace] map size={len(workspace_map)} sample keys={list(workspace_map.keys())[:5]}")
                sample_search_ids = []
                sample_saved_ids = []
                sample_in_map = []
                for s in enriched_searches[:5]:
                    sid = str(s.get("id") or s.get("savedSearchId") or "<none>")
                    sample_search_ids.append(sid)
                    sample_saved_ids.append(str(s.get("savedSearchId") or "<none>"))
                    sample_in_map.append("yes" if sid in workspace_map else "no")
                logger.info(f"[workspace] first 5 search ids from enriched_searches id={sample_search_ids} savedSearchId={sample_saved_ids} in_map={sample_in_map}")

                if workspace_map:
                    matched = 0
                    for search in enriched_searches:
                        sid = str(search.get("id") or search.get("savedSearchId") or "")
                        if sid:
                            ws = workspace_map.get(sid)
                            if ws:
                                matched += 1
                                search["workspaceId"] = ws.get("workspaceId")
                                search["workspaceName"] = ws.get("workspaceName")
                    logger.info(f"Workspace enrichment matched {matched} searches")

                for search in enriched_searches:
                    search.setdefault("workspaceId", None)
                    search.setdefault("workspaceName", "Admin Workspace")

                if enriched_searches and len(enriched_searches) > 0:
                    first = enriched_searches[0]
                    logger.info(f"First item sample keys: {list(first.keys())[:10]}")
                    # Log if any user enrichment fields were added
                    user_enrichment_fields = [
                        k
                        for k in first.keys()
                        if k.endswith("_Name") or k.endswith("_Email")
                    ]
                    if user_enrichment_fields:
                        logger.info(
                            f"User enrichment fields found: {user_enrichment_fields}"
                        )

                # Ensure all enrichment fields are present (fix for missing columns in CSV)
                if enriched_searches:
                    # Collect all enrichment fields from the data
                    all_enrichment_fields = set()
                    for search in enriched_searches:
                        for key in search.keys():
                            if key.endswith("_Name") or key.endswith("_Email"):
                                all_enrichment_fields.add(key)
                    
                    # Add missing enrichment fields to each search
                    for search in enriched_searches:
                        for field in all_enrichment_fields:
                            if field not in search:
                                search[field] = ""
                    logger.info(f"Ensured {len(all_enrichment_fields)} enrichment fields are present in all searches")

                # Filter by specific search names if provided
                filtered_searches = enriched_searches
                unmatched_names = []

                # Debug: Log sample search names from API
                sample_api_names = []
                for search in enriched_searches[:10]:
                    search_name = (
                        search.get("label")
                        or search.get("name")
                        or search.get("searchName")
                        or search.get("queryName")
                        or ""
                    )
                    sample_api_names.append(search_name)
                logger.info(f"Sample API search names: {sample_api_names}")

                if filter_names:
                    # Create a set of lowercase filter names for case-insensitive matching
                    filter_set = set(name.lower().strip() for name in filter_names)
                    matched_names = set()
                    filtered_searches = []
                    for search in enriched_searches:
                        # Check various possible name fields in the search object
                        search_name = (
                            search.get("label")
                            or search.get("name")
                            or search.get("searchName")
                            or search.get("queryName")
                            or ""
                        )
                        search_name_lower = search_name.lower().strip()
                        if search_name_lower in filter_set:
                            filtered_searches.append(search)
                            matched_names.add(search_name_lower)

                    # Find unmatched names
                    unmatched_names = [
                        name
                        for name in filter_names
                        if name.lower().strip() not in matched_names
                    ]
                    logger.info(
                        f"Filtered to {len(filtered_searches)} searches matching the {len(filter_names)} provided names"
                    )
                    logger.info(f"Unmatched names: {len(unmatched_names)}")

                return {
                    "data": filtered_searches,
                    "meta": {
                        "totalCount": len(filtered_searches),
                        "companyId": company_id,
                        "userMapping": len(user_map) > 0,
                        "debug_user_count": unique_count,
                        "debug_sample_mapping": list(user_map.keys())[:20]
                        if user_map
                        else [],
                        "filterApplied": len(filter_names) > 0
                        if filter_names
                        else False,
                        "unmatchedNames": unmatched_names,
                    },
                }

            except httpx.TimeoutException:
                logger.error(
                    "Timeout fetching searches, retrying with extended timeout..."
                )
                # Retry with even longer timeout
                try:
                    resp = await client.get(search_url, headers=headers, timeout=600.0)
                    if resp.status_code == 200:
                        data = resp.json()
                        if isinstance(data, dict):
                            searches = data.get("searches") or data.get("data") or []
                        else:
                            searches = data if isinstance(data, list) else []
                        logger.info(
                            f"Retry successful, fetched {len(searches)} searches"
                        )

                        # Wait for user map and enrich results
                        try:
                            user_map_result = await user_map_task
                            user_map, unique_count = user_map_result
                        except Exception as e:
                            logger.warning(f"Failed to get user map: {e}")
                            user_map = {}
                            unique_count = 0

                        # Enrich searches with user data
                        logger.info(
                            f"Enriching {len(searches)} searches with user_map({len(user_map)}) using companyId: {company_id}"
                        )
                        enriched_searches = [
                            deep_enrich(item, user_map, {}) for item in searches
                        ]
                        # Ensure all enrichment fields are present (fix for CSV columns)
                        enriched_searches = ensure_enrichment_fields(enriched_searches)
                        # Convert epoch timestamps to human-readable format
                        enriched_searches = convert_timestamps(enriched_searches)

                        # Filter by specific search names if provided
                        filtered_searches = enriched_searches
                        unmatched_names = []

                        if filter_names:
                            # Create a set of lowercase filter names for case-insensitive matching
                            filter_set = set(
                                name.lower().strip() for name in filter_names
                            )
                            matched_names = set()
                            filtered_searches = []
                            for search in enriched_searches:
                                # Check various possible name fields in the search object
                                search_name = (
                                    search.get("label")
                                    or search.get("name")
                                    or search.get("searchName")
                                    or search.get("queryName")
                                    or ""
                                )
                                search_name_lower = search_name.lower().strip()
                                if search_name_lower in filter_set:
                                    filtered_searches.append(search)
                                    matched_names.add(search_name_lower)

                            # Find unmatched names
                            unmatched_names = [
                                name
                                for name in filter_names
                                if name.lower().strip() not in matched_names
                            ]
                            logger.info(
                                f"Filtered to {len(filtered_searches)} searches matching the {len(filter_names)} provided names"
                            )

                        return {
                            "data": filtered_searches,
                            "meta": {
                                "totalCount": len(filtered_searches),
                                "companyId": company_id,
                                "userMapping": len(user_map) > 0,
                                "debug_user_count": unique_count,
                                "debug_sample_mapping": list(user_map.keys())[:20]
                                if user_map
                                else [],
                                "filterApplied": len(filter_names) > 0
                                if filter_names
                                else False,
                                "unmatchedNames": unmatched_names,
                            },
                        }
                except Exception as retry_err:
                    logger.error(f"Retry failed: {retry_err}")
                    return {
                        "error": True,
                        "status": 500,
                        "message": f"Request timed out: {str(retry_err)}",
                    }
                except Exception as e:
                    logger.error(f"Error fetching searches: {e}")
                    return {
                        "error": True,
                        "status": 500,
                        "message": f"Request failed: {str(e)}",
                    }

    except Exception as e:
        logger.error(f"List searches request failed: {e}")
        logger.exception("Full exception details:")
        return {
            "error": True,
            "status": 500,
            "message": f"List searches request failed: {str(e)}",
            "data": None,
        }


async def unified_account_discovery_handler(
    token: str, placeholders: Dict[str, str] = None
) -> Dict[str, Any]:
    """
    ULTIMATE UNIFIED VIEW: Combines All Searches (Basic + E+), Users, Usage,
    and Maps them into a single refined dataset with name/email mapping.

    Supports optional filtering:
    - filterAccountNames: Filter by specific account names (one per line, case-insensitive)
    """
    logger.info("=== UNIFIED ACCOUNT DISCOVERY HANDLER START ===")
    logger.info(f"Placeholders received: {placeholders}")
    import jwt
    from datetime import datetime

    def format_ts(ts):
        if not ts:
            return None
        try:
            if isinstance(ts, (int, float)):
                if ts > 1e11:
                    ts = ts / 1000.0
                return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            return str(ts)
        except:
            return str(ts)

    def get_search_query(s):
        # Try various common field names for query/bool
        q = s.get("query") or s.get("searchQuery") or s.get("boolQuery")
        if not q and "logic" in s:
            logic = s.get("logic", {})
            if isinstance(logic, dict):
                q = logic.get("query") or logic.get("bool") or logic.get("text")
        if not q and "searchQueries" in s:
            sq = s.get("searchQueries", [])
            if sq and isinstance(sq, list) and len(sq) > 0:
                q = sq[0].get("query")
        return q or ""

    def get_search_type(s, default="SEARCH"):
        return s.get("searchType") or s.get("type") or s.get("category") or default

    try:
        # 1. Decode token for companyId
        decoded_token = jwt.decode(token, options={"verify_signature": False})
        company_id = decoded_token.get("company", {}).get("_id") or decoded_token.get(
            "user", {}
        ).get("activeCompanyId")

        if not company_id:
            return {
                "error": True,
                "status": 400,
                "message": "Could not identify companyId from token",
            }

        # 2. Fetch Users (for ID -> Name/Email mapping)
        logger.info("Fetching users for mapping...")
        users_result = await list_users_complete_handler(token)
        user_map = {}  # id -> {name, email}
        if not users_result.get("error"):
            for u in users_result.get("data", []):
                uid = u.get("_id")
                first = u.get("firstName", "")
                last = u.get("lastName", "")
                email = u.get("email", "")
                user_map[uid] = {
                    "name": f"{first} {last}".strip() or "Unknown User",
                    "email": email,
                }

        async with httpx.AsyncClient(timeout=60.0) as client:
            # Comprehensive headers (matching other working handlers)
            headers = {
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
                "Origin": "https://app.meltwater.com",
                "Referer": "https://app.meltwater.com/",
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
                "sec-ch-ua": '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"macOS"',
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "cross-site",
                "X-Client-Name": "mi-web-app",
            }

            # 3. Fetch Regular Searches (v2)
            logger.info("Fetching Regular searches...")
            reg_resp = await client.get(
                f"https://masfsearch.meltwater.io/masfsearch/v2/search/list/{company_id}",
                headers=headers,
            )
            reg_searches = reg_resp.json() if reg_resp.status_code == 200 else []
            if not isinstance(reg_searches, list):
                logger.warning(
                    f"Regular searches response not a list: {type(reg_searches)}"
                )
                reg_searches = []

            # 4. Fetch Explore+ Searches
            logger.info("Fetching Explore+ searches...")
            ep_url = f"https://r4dar-darlyng-prod.meltwater.io/1.0/accounts/{company_id}/queries/search"
            ep_body = {
                "showHidden": True,
                "type": "Query",
                "tab": "account",
                "pagination": {"count": 1000, "offset": 0},
            }
            ep_resp = await client.post(ep_url, json=ep_body, headers=headers)
            ep_data = ep_resp.json() if ep_resp.status_code == 200 else {}
            ep_searches = ep_data.get("results", [])

            # 5. Extract IDs for Usage Lookup
            search_ids = []
            seen_ids = set()

            def add_id(sid):
                if sid:
                    s = str(sid)
                    if s not in seen_ids:
                        seen_ids.add(s)
                        search_ids.append(s)

            for s in reg_searches:
                add_id(s.get("savedSearchId") or s.get("id"))
            for s in ep_searches:
                add_id(s.get("id"))

            # 6. Fetch Usage Data
            usage_map = {}
            if search_ids:
                logger.info(f"Fetching usage for {len(search_ids)} searches...")
                u_url = (
                    "https://discovery-next-mw-apollo-production.meltwater.io/graphql"
                )
                # Use EXACT headers from the working search_usage_handler
                u_headers = {
                    "User-Agent": headers["User-Agent"],
                    "Origin": headers["Origin"],
                    "Referer": headers["Referer"],
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {token}",
                    "apollographql-client-name": "discovery-next",
                    "apollographql-client-version": "0.0.0",
                    "sec-ch-ua": headers["sec-ch-ua"],
                    "sec-ch-ua-mobile": headers["sec-ch-ua-mobile"],
                    "sec-ch-ua-platform": headers["sec-ch-ua-platform"],
                    "Sec-Fetch-Dest": "empty",
                    "Sec-Fetch-Mode": "cors",
                    "Sec-Fetch-Site": "cross-site",
                }
                u_body = {
                    "operationName": "searchUsagesByIds",
                    "variables": {"ids": search_ids},
                    "query": """query searchUsagesByIds($ids: [ID!]) {
                        searchUsagesByIds(ids: $ids) {
                            id
                            usages {
                                alerts { id name }
                                combinations { id name }
                                dashboards { id name }
                                digests { id name }
                                monitors { id name }
                            }
                        }
                    }""",
                }
                u_resp = await client.post(u_url, json=u_body, headers=u_headers)
                if u_resp.status_code == 200:
                    u_json = u_resp.json()
                    u_data = u_json.get("data", {}).get("searchUsagesByIds", []) or []
                    if u_json.get("errors"):
                        logger.error(
                            f"Usage API returned errors: {u_json.get('errors')}"
                        )

                    for item in u_data:
                        if item and "id" in item:
                            usage_map[str(item["id"])] = item.get("usages", {})
                    logger.info(
                        f"Successfully mapped usage for {len(usage_map)} searches"
                    )
                else:
                    logger.error(
                        f"Usage API failed with status {u_resp.status_code}: {u_resp.text[:200]}"
                    )

            # 7. UNIFY AND REFINE DATA
            unified_results = []

            # Process Regular Searches
            for s in reg_searches:
                sid = str(s.get("savedSearchId") or s.get("id"))
                usage = usage_map.get(sid, {})

                # Updated By mapping with fallbacks
                ub_id = (
                    s.get("updatedBy")
                    or s.get("lastModifiedBy")
                    or s.get("updatedByUserId")
                )
                ub_info = user_map.get(ub_id, {"name": ub_id or "System", "email": ""})

                # Usage summary
                summary = {
                    k: len(v) if isinstance(v, list) else 0 for k, v in usage.items()
                }
                total_usage = sum(summary.values())

                refined = {
                    "id": sid,
                    "name": s.get("name") or s.get("searchName"),
                    "type": "Regular",
                    "updatedAt": format_ts(
                        s.get("updatedAt")
                        or s.get("updatedTime")
                        or s.get("lastModified")
                    ),
                    "updatedBy": ub_info["name"],
                    "updatedByEmail": ub_info["email"],
                    "query": get_search_query(s),
                    "searchType": "EXPLORE_REGULAR",
                    "usageCount": total_usage,
                    "isUsed": total_usage > 0,
                    "usageSummary": summary,
                    "usageDetails": usage,
                }
                unified_results.append(refined)

            # Process Explore+ Searches (avoid duplicates if same ID exists)
            for s in ep_searches:
                sid = str(s.get("id"))
                if sid in [r["id"] for r in unified_results]:
                    continue

                usage = usage_map.get(sid, {})

                ub_id = s.get("updatedBy") or s.get("lastModifiedBy")
                ub_info = user_map.get(ub_id, {"name": ub_id or "System", "email": ""})

                summary = {
                    k: len(v) if isinstance(v, list) else 0 for k, v in usage.items()
                }
                total_usage = sum(summary.values())

                refined = {
                    "id": sid,
                    "name": s.get("name") or s.get("label") or s.get("title"),
                    "type": "Explore+",
                    "updatedAt": format_ts(
                        s.get("updatedAt")
                        or s.get("modified")
                        or s.get("lastModified")
                        or s.get("lastUpdated")
                    ),
                    "updatedBy": ub_info["name"],
                    "updatedByEmail": ub_info["email"],
                    "query": get_search_query(s),
                    "searchType": "EXPLORE_PLUS",
                    "usageCount": total_usage,
                    "isUsed": total_usage > 0,
                    "usageSummary": summary,
                    "usageDetails": usage,
                }
                unified_results.append(refined)

            # Final Sort: Used first, then by name
            unified_results.sort(
                key=lambda x: (-x["usageCount"], (x["name"] or "").lower())
            )

            # Filter by specific account names if provided
            filter_account_names_raw = (placeholders or {}).get(
                "filterAccountNames"
            ) or ""
            filter_account_names = []
            if filter_account_names_raw:
                # Split by newlines and clean up
                filter_account_names = [
                    name.strip()
                    for name in filter_account_names_raw.split("\n")
                    if name.strip()
                ]
                logger.info(
                    f"Filtering by {len(filter_account_names)} specific account names"
                )

            filtered_results = unified_results
            unmatched_names = []

            if filter_account_names:
                # Debug: Log sample data fields
                if unified_results:
                    logger.info(
                        f"Sample result keys: {list(unified_results[0].keys())}"
                    )
                    logger.info(
                        f"Sample result name field: {unified_results[0].get('name')}"
                    )

                # Create a set of lowercase filter names for case-insensitive matching
                filter_set = set(name.lower().strip() for name in filter_account_names)
                matched_names = set()
                filtered_results = []
                for result in unified_results:
                    # Check various possible name fields in the result object
                    account_name = (
                        result.get("name")
                        or result.get("label")
                        or result.get("title")
                        or ""
                    )
                    account_name_lower = account_name.lower().strip()
                    if account_name_lower in filter_set:
                        filtered_results.append(result)
                        matched_names.add(account_name_lower)

                # Find unmatched names
                unmatched_names = [
                    name
                    for name in filter_account_names
                    if name.lower().strip() not in matched_names
                ]
                logger.info(f"Filtering by account names: {filter_account_names}")
                logger.info(f"Filter set: {filter_set}")
                logger.info(
                    f"Filtered to {len(filtered_results)} results matching the {len(filter_account_names)} provided account names"
                )
                logger.info(f"Matched names: {matched_names}")
                logger.info(f"Unmatched names: {unmatched_names}")

            return {
                "success": True,
                "data": filtered_results,
                "meta": {
                    "totalCount": len(filtered_results),
                    "usedCount": len([r for r in filtered_results if r["isUsed"]]),
                    "companyId": company_id,
                    "filterApplied": len(filter_account_names) > 0
                    if filter_account_names
                    else False,
                    "unmatchedNames": unmatched_names,
                },
            }

    except Exception as e:
        logger.error(f"Unified handler failed: {e}")
        logger.exception("Unified handler exception:")
        return {"error": True, "status": 500, "message": str(e)}


async def author_lists_handler(token: str, placeholders: Dict[str, str]) -> Dict[str, Any]:
    """
    Fetch all Explore Author Lists with all handles/sources per list.
    Endpoint chain:
      - GET  https://r4dar-darlyng-prod.meltwater.io/2.0/accounts/{companyId}/author-lists/search
      - GET  https://r4dar-darlyng-prod.meltwater.io/2.0/accounts/{companyId}/author-lists/{listId}/sources/search
    Each row in the output = one (authorList, handle/source) pair flattened for CSV.
    """
    logger.info("=== EXPLORE AUTHOR LISTS (LABELS) HANDLER START ===")

    company_id = placeholders.get("companyId") or placeholders.get("accountId")
    if not company_id:
        try:
            import jwt as _jwt
            decoded = _jwt.decode(token, options={"verify_signature": False})
            company_id = decoded.get("company", {}).get("_id") or decoded.get("user", {}).get("activeCompanyId")
        except Exception:
            pass
    if not company_id:
        return {"error": True, "status": 400, "message": "companyId is required"}

    base_headers = {
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive",
        "Origin": "https://app.meltwater.com",
        "Referer": "https://app.meltwater.com/",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "cross-site",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
        "Authorization": f"Bearer {token}",
        "sec-ch-ua": '"Google Chrome";v="149", "Chromium";v="149", "Not)A;Brand";v="24"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"macOS"',
    }

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            # Step 1: list all author lists
            lists_url = f"https://r4dar-darlyng-prod.meltwater.io/2.0/accounts/{company_id}/author-lists/search"
            logger.info(f"Fetching author lists from {lists_url}")
            lists_resp = await client.post(
                lists_url,
                headers={**base_headers, "content-type": "application/json"},
                json={"pagination": {"count": 100, "offset": 0, "sortOrder": "asc", "sortBy": "label"}, "textSearch": ""},
            )
            lists_resp.raise_for_status()
            lists_payload = lists_resp.json()
            author_lists = []
            if isinstance(lists_payload, list):
                author_lists = lists_payload
            elif isinstance(lists_payload, dict):
                extracted = lists_payload.get("authorLists") or lists_payload.get("author_labels") or lists_payload.get("data") or lists_payload.get("items") or []
                if isinstance(extracted, dict):
                    extracted = extracted.get("data") or extracted.get("items") or []
                author_lists = extracted if isinstance(extracted, list) else []
            logger.info(f"Found {len(author_lists)} author lists on first page")

            if not author_lists:
                return {"data": [], "summary": {"totalLists": 0, "totalHandles": 0}}

            semaphore = asyncio.Semaphore(5)

            async def fetch_sources(list_obj):
                list_id = str(list_obj.get("_id") or list_obj.get("id") or list_obj.get("listId") or "")
                list_name = list_obj.get("name") or list_obj.get("label") or list_obj.get("title") or ""
                if not list_id:
                    return []
                url = f"https://r4dar-darlyng-prod.meltwater.io/2.0/accounts/{company_id}/author-lists/{list_id}/sources/search"
                rows = []
                offset = 0
                page_size = 200
                while True:
                    try:
                        async with semaphore:
                            body = {"pagination": {"count": page_size, "offset": offset, "sortOrder": "asc", "sortBy": "id"}, "textSearch": ""}
                            resp = await client.post(url, headers={**base_headers, "content-type": "application/json"}, json=body, timeout=30.0)
                        if resp.status_code != 200:
                            logger.warning(f"Sources fetch failed for list {list_id} offset={offset}: {resp.status_code} body={resp.text[:300]}")
                            break
                        data = resp.json()
                        sources = []
                        if isinstance(data, list):
                            sources = data
                        elif isinstance(data, dict):
                            sources = data.get("sources") or data.get("handles") or data.get("items") or data.get("data") or []
                        if not sources:
                            break
                        for src in sources:
                            source_type = src.get("sourceType") or src.get("source_type") or ""
                            profile_url = src.get("profileUrl") or src.get("url") or src.get("link") or ""
                            handle = src.get("handle") or src.get("username") or src.get("name") or ""
                            author_id = src.get("_id") or src.get("id") or ""
                            rows.append({
                                "authorListId": list_id,
                                "authorListName": list_name,
                                "authorId": author_id,
                                "handle": handle,
                                "profileUrl": profile_url,
                                "sourceType": source_type,
                                "raw": src,
                            })
                        if len(sources) < page_size:
                            break
                        offset += page_size
                    except Exception as exc:
                        logger.warning(f"Sources fetch exception for list {list_id} offset={offset}: {exc}")
                        break
                return rows

            results = await asyncio.gather(*[fetch_sources(al) for al in author_lists])
            flat = []
            for batch in results:
                flat.extend(batch)

            logger.info(f"Author lists export: {len(author_lists)} lists, {len(flat)} handles")

            return {
                "data": flat,
                "summary": {
                    "totalLists": len(author_lists),
                    "totalHandles": len(flat),
                },
            }

    except Exception as e:
        logger.error(f"Explore author lists handler failed: {e}")
        logger.exception("Explore author lists exception:")
        return {"error": True, "status": 500, "message": str(e)}


async def monitored_pages_handler(
    token: str, placeholders: Dict[str, str], provider_filter: Optional[int] = None
) -> Dict[str, Any]:
    """
    Step 1: Discover all linked FB and IG accounts for a company using companyId.
    Step 2: Pull subscriptions for each discovered account.
    Step 3: Enrich with user data (names/emails).
    """
    logger.info("=== MONITORED PAGES COMPOSITE HANDLER START ===")
    logger.info(f"Placeholders received: {placeholders}")
    import jwt
    import asyncio

    try:
        company_id = placeholders.get("companyId")
        if not company_id:
            return {"error": True, "status": 400, "message": "companyId is required"}

        # Extract userId from token
        decoded_token = jwt.decode(token, options={"verify_signature": False})
        user_id = decoded_token.get("user", {}).get("_id") or decoded_token.get("uid")

        if not user_id:
            return {
                "error": True,
                "status": 400,
                "message": "Could not extract userId from token",
            }

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
            "Origin": "https://app.meltwater.com",
            "Referer": "https://app.meltwater.com/",
        }

        # Pre-fetch user map for enrichment (parallel with other operations)
        logger.info(
            f"Pre-fetching user map for enrichment (companyId: {company_id})..."
        )
        user_map_task = get_user_map(token, company_id=company_id)

        # Step 1: Discover Social Accounts (Section 31 GraphQL)
        logger.info(
            f"Step 1: Discovering social accounts for company {company_id} (userId: {user_id})"
        )
        s31_url = "https://section-31-graph.section31.meltwater.io/graphql"

        # EXACT query and variables from presets.ts to ensure compatibility
        s31_query = {
            "query": """query CompanyCredentialsFilteredQuery($query: FilteredCompanyCredentials, $withLogo: Boolean!, $withXPremium: Boolean!, $withPermissions: Boolean!, $withToken: Boolean!) {
              companyCredentialsFilteredQuery(query: $query) {
                channelId
                channelName
                socialAccountId
                targetPageName
                username
                targetPageLogoUrl @include(if: $withLogo)
                xPremiumAccount @include(if: $withXPremium)
                permission @include(if: $withPermissions) {
                  _id
                  approver
                }
                tokenDetails @include(if: $withToken) {
                  expiryDate
                }
              }
            }""",
            "variables": {
                "withLogo": True,
                "withPermissions": False,
                "withToken": True,
                "withXPremium": False,
                "query": {
                    "applicationCompanyId": company_id,
                    "userId": user_id,
                },
            },
        }

        async with httpx.AsyncClient(timeout=60.0) as client:
            # STRATEGY 1: Direct Company-Wide Subscriptions + Account Mapping
            # We run these in parallel to avoid timeouts and improve speed
            account_name_map = {}
            if provider_filter:
                logger.info(
                    f"Attempting Strategy 1 (Parallel): Accounts + Subscriptions for provider {provider_filter}"
                )

                accounts_url = f"https://unified-subscription.northeurope.k8s-cobalt.azure.meltwater.io/v1/companies/{company_id}/provider/{provider_filter}/accounts"
                subs_url = f"https://unified-subscription.northeurope.k8s-cobalt.azure.meltwater.io/v1/companies/{company_id}/provider/{provider_filter}/subscriptions?workspaceId=ALL"

                try:
                    # Parallel fetch (including user map)
                    acc_task = client.get(
                        accounts_url,
                        headers={**headers, "x-client-name": "inception-subscriptions"},
                    )
                    subs_task = client.get(
                        subs_url,
                        headers={**headers, "x-client-name": "inception-subscriptions"},
                    )

                    acc_resp, subs_resp, user_map_result = await asyncio.gather(
                        acc_task, subs_task, user_map_task
                    )
                    user_map, unique_count = user_map_result

                    # 1. Map account names
                    if acc_resp.status_code == 200:
                        acc_list = acc_resp.json()
                        if isinstance(acc_list, list):
                            for item in acc_list:
                                acc_obj = item.get("account", {})
                                acc_id = str(acc_obj.get("id"))
                                acc_name = acc_obj.get("name")
                                if acc_id and acc_name:
                                    account_name_map[acc_id] = acc_name
                            logger.info(f"Mapped {len(account_name_map)} account names")
                    else:
                        logger.warning(
                            f"Accounts metadata failed with status {acc_resp.status_code}"
                        )

                    # 2. Process subscriptions
                    if subs_resp.status_code == 200:
                        data = subs_resp.json()
                        if isinstance(data, list) and len(data) > 0:
                            logger.info(
                                f"Strategy 1 SUCCESS: Found {len(data)} subscriptions"
                            )
                            results = []
                            for item in data:
                                cur_acc_id = str(item.get("accountId"))
                                
                                logger.info(
    f"accountId={cur_acc_id}, map={account_name_map.get(cur_acc_id)}, apiAccountName={item.get('accountName')}"
)
                                results.append(
                                       {
        "platform": "facebook"
        if provider_filter == 5
        else "instagram",
        "accountId": cur_acc_id or "Unknown",
        "accountName": account_name_map.get(cur_acc_id)
        or item.get("accountName")
        or "Unknown",

        **{
            k: v
            for k, v in item.items()
            if k not in ("platform", "accountId", "accountName")
        },
    }
)
                                logger.info(f"Final accountName: {results[-1].get('accountName')}")

                            # Sort by accountId to group pages together
                            results.sort(key=lambda x: str(x.get("accountId", "")))

                            # Debug: Log sample fields from first result to understand data structure
                            if results:
                                sample_fields = {
                                    k: type(v).__name__
                                    for k, v in results[0].items()
                                    if any(
                                        uid in k.lower()
                                        for uid in [
                                            "user",
                                            "by",
                                            "owner",
                                            "creator",
                                            "author",
                                        ]
                                    )
                                }
                                logger.info(
                                    f"Strategy 1 Sample user-related fields: {sample_fields}"
                                )

                            # Enrich results with user data
                            logger.info(
                                f"Enriching {len(results)} subscriptions with user_map({len(user_map)}) using companyId: {company_id}"
                            )
                            enriched = [
                                deep_enrich(item, user_map, {}) for item in results
                            ]
                            enriched = ensure_enrichment_fields(enriched)
                            enriched = convert_timestamps(enriched)

                            # Get current company info
                            company_info = await get_current_company_info(token)

                            # Apply filter by account names if provided (for provider 5 = Facebook)
                            filter_account_names_raw = (
                                placeholders.get("filterAccountNames") or ""
                            )
                            filter_account_names = []
                            if filter_account_names_raw:
                                filter_account_names = [
                                    name.strip()
                                    for name in filter_account_names_raw.split("\n")
                                    if name.strip()
                                ]
                                logger.info(
                                    f"Strategy 1: Filtering by {len(filter_account_names)} account names"
                                )

                            filtered_enriched = enriched
                            unmatched_names = []
                            if filter_account_names and provider_filter in [
                                5,
                                3,
                            ]:  # 5 = Facebook, 3 = Instagram
                                filter_set = set(
                                    name.lower().strip()
                                    for name in filter_account_names
                                )
                                matched_names = set()
                                filtered_enriched = []
                                for item in enriched:
                                    account_name = (
                                        item.get("accountName")
                                        or item.get("targetPageName")
                                        or ""
                                    )
                                    account_name_lower = account_name.lower().strip()
                                    if account_name_lower in filter_set:
                                        filtered_enriched.append(item)
                                        matched_names.add(account_name_lower)
                                unmatched_names = [
                                    name
                                    for name in filter_account_names
                                    if name.lower().strip() not in matched_names
                                ]
                                logger.info(
                                    f"Strategy 1: Filtered to {len(filtered_enriched)} results (from {len(enriched)}) for provider {provider_filter}"
                                )

                            # Apply criteriaType filter for Instagram (topics vs hashtags) in Strategy 1
                            if provider_filter == 3:
                                ig_content_type = placeholders.get(
                                    "igContentType", "all"
                                ).lower()
                                if ig_content_type != "all":
                                    logger.info(
                                        f"Strategy 1: Applying criteriaType filter: {ig_content_type}"
                                    )
                                    if ig_content_type == "topics":
                                        filtered_enriched = [
                                            item
                                            for item in filtered_enriched
                                            if item.get("providerSpecific", {}).get(
                                                "criteriaType"
                                            )
                                            == "topics"
                                        ]
                                        logger.info(
                                            f"Strategy 1: Filtered to {len(filtered_enriched)} topics (pages) only"
                                        )
                                    elif ig_content_type == "hashtags":
                                        filtered_enriched = [
                                            item
                                            for item in filtered_enriched
                                            if item.get("providerSpecific", {}).get(
                                                "criteriaType"
                                            )
                                            == "hashtags"
                                        ]
                                        logger.info(
                                            f"Strategy 1: Filtered to {len(filtered_enriched)} hashtags only"
                                        )

                            return {
                                "data": filtered_enriched,
                                "meta": {
                                    "totalSubscriptions": len(enriched),
                                    "companyId": company_id,
                                    "currentCompany": company_info,
                                    "method": "direct_parallel_listing",
                                    "userMapping": len(user_map) > 0,
                                    "debug_user_count": unique_count,
                                    "mappedNames": len(
                                        [
                                            r
                                            for r in enriched
                                            if r.get("accountName") != "Unknown"
                                        ]
                                    ),
                                },
                            }
                        else:
                            logger.info(
                                "Strategy 1 returned empty subscriptions list, falling back to Section 31"
                            )
                    else:
                        logger.info(
                            f"Strategy 1 (Subscriptions) failed with status {subs_resp.status_code}, falling back to Section 31"
                        )
                except Exception as e:
                    logger.error(f"Strategy 1 Error: {e}")

            # STRATEGY 2: Section 31 Discovery (Fallback)
            logger.info(
                f"Strategy 2: Discovering social accounts for company {company_id} via Section 31"
            )
            s31_url = "https://section-31-graph.section31.meltwater.io/graphql"

            # FIXED query (no unused variables to avoid 400 error)
            s31_query = {
                "query": """query CompanyCredentialsFilteredQuery($query: FilteredCompanyCredentials) {
                  companyCredentialsFilteredQuery(query: $query) {
                    channelId
                    channelName
                    socialAccountId
                    targetPageName
                    username
                  }
                }""",
                "variables": {
                    "query": {
                        "applicationCompanyId": company_id,
                        "userId": user_id,
                    },
                },
            }

            # Wait for user map if not already resolved in Strategy 1
            try:
                user_map_result = await user_map_task
                user_map, unique_count = user_map_result
            except Exception as e:
                logger.warning(f"Failed to get user map: {e}")
                user_map = {}
                unique_count = 0

            logger.info(f"Sending Section 31 request for company {company_id}...")
            # ... rest of the Section 31 logic ...

            logger.info(f"Sending Section 31 request for company {company_id}...")
            s31_resp = await client.post(
                s31_url,
                json=s31_query,
                headers={**headers, "Accept": "application/graphql-response+json"},
            )

            credentials = []
            if s31_resp.status_code == 200:
                s31_data = s31_resp.json()
                credentials = s31_data.get("data", {}).get(
                    "companyCredentialsFilteredQuery", []
                )
            else:
                logger.error(
                    f"Strategy 2 Initial Attempt failed with status {s31_resp.status_code}: {s31_resp.text}"
                )

            if not credentials:
                logger.warning(
                    f"Strategy 2 returned NO credentials. Final discovery attempt failed."
                )
            else:
                logger.info(
                    f"Section 31 successfully found {len(credentials)} total credentials."
                )

            # Filter for Facebook (5) and Instagram (3)
            fb_accounts = [c for c in credentials if c.get("channelId") == 5]
            ig_accounts = [c for c in credentials if c.get("channelId") == 3]

            # Apply provider filter if specified
            if provider_filter == 5:
                # Only FB
                ig_accounts = []
            elif provider_filter == 3:
                # Only IG
                fb_accounts = []

            logger.info(
                f"Filtered accounts: {len(fb_accounts)} FB, {len(ig_accounts)} IG"
            )

            # Step 2: Fetch Subscriptions per account
            async def fetch_subs(account, provider_id):
                acc_id = account.get("socialAccountId")
                acc_name = (
                    account.get("targetPageName")
                    or account.get("username")
                    or "Unknown"
                )
                url = f"https://unified-subscription.northeurope.k8s-cobalt.azure.meltwater.io/v1/companies/{company_id}/provider/{provider_id}/accounts/{acc_id}/subscriptions"

                try:
                    resp = await client.get(
                        url,
                        headers={**headers, "x-client-name": "inception-subscriptions"},
                    )
                    if resp.status_code == 200:
                        return {
                            "accountId": acc_id,
                            "accountName": acc_name,
                            "subscriptions": resp.json(),
                        }
                    else:
                        logger.warning(
                            f"Failed to fetch subs for {acc_id} (provider {provider_id}): {resp.status_code}"
                        )
                        return {
                            "accountId": acc_id,
                            "accountName": acc_name,
                            "error": f"Status {resp.status_code}",
                            "subscriptions": [],
                        }
                except Exception as e:
                    logger.error(f"Error fetching subs for {acc_id}: {e}")
                    return {
                        "accountId": acc_id,
                        "accountName": acc_name,
                        "error": str(e),
                        "subscriptions": [],
                    }

            # Gather all requests
            tasks = []
            for acc in fb_accounts:
                tasks.append(fetch_subs(acc, 5))
            for acc in ig_accounts:
                tasks.append(fetch_subs(acc, 3))

            results = await asyncio.gather(*tasks)

            fb_results = []
            ig_results = []
            total_subs = 0

            # Map results back to platforms
            fb_ids = {acc.get("socialAccountId") for acc in fb_accounts}
            for res in results:
                platform = "facebook" if res["accountId"] in fb_ids else "instagram"

                # Flatten the sub-items for a cleaner unified list if needed
                subs = res.get("subscriptions", [])
                refined_subs = []
                if isinstance(subs, list):
                    for s in subs:
                        refined_subs.append(
                            {
                                "platform": platform,
                                "accountId": res["accountId"],
                                "accountName": res["accountName"],
                                **s,
                            }
                        )
                    total_subs += len(subs)

                if platform == "facebook":
                    fb_results.extend(refined_subs)
                else:
                    ig_results.extend(refined_subs)

            # Sort results by accountId to group pages together
            fb_results.sort(key=lambda x: str(x.get("accountId", "")))
            ig_results.sort(key=lambda x: str(x.get("accountId", "")))

            # Enrich results with user data
            logger.info(
                f"Enriching results with user_map({len(user_map)}) using companyId: {company_id}"
            )

            # Debug: Log sample fields from first result to understand data structure
            if fb_results:
                sample_fields = {
                    k: type(v).__name__
                    for k, v in fb_results[0].items()
                    if any(
                        uid in k.lower()
                        for uid in ["user", "by", "owner", "creator", "author"]
                    )
                }
                logger.info(f"FB Sample user-related fields: {sample_fields}")
            if ig_results:
                sample_fields = {
                    k: type(v).__name__
                    for k, v in ig_results[0].items()
                    if any(
                        uid in k.lower()
                        for uid in ["user", "by", "owner", "creator", "author"]
                    )
                }
                logger.info(f"IG Sample user-related fields: {sample_fields}")

            fb_enriched = [deep_enrich(item, user_map, {}) for item in fb_results]
            ig_enriched = [deep_enrich(item, user_map, {}) for item in ig_results]
            fb_enriched = ensure_enrichment_fields(fb_enriched)
            fb_enriched = convert_timestamps(fb_enriched)
            ig_enriched = ensure_enrichment_fields(ig_enriched)
            ig_enriched = convert_timestamps(ig_enriched)

            # Get current company info
            company_info = await get_current_company_info(token)

            # Filter by specific account names if provided
            filter_account_names_raw = placeholders.get("filterAccountNames") or ""
            filter_account_names = []
            if filter_account_names_raw:
                # Split by newlines and clean up
                filter_account_names = [
                    name.strip()
                    for name in filter_account_names_raw.split("\n")
                    if name.strip()
                ]
                logger.info(
                    f"Filtering by {len(filter_account_names)} specific account names"
                )

            # Apply filter to Facebook results
            # Filter by specific account names if provided
            filter_account_names_raw = placeholders.get("filterAccountNames") or ""
            filter_account_names = []
            if filter_account_names_raw:
                filter_account_names = [
                    name.strip()
                    for name in filter_account_names_raw.split("\n")
                    if name.strip()
                ]
                logger.info(f"filterAccountNames raw: '{filter_account_names_raw}'")
                logger.info(f"filterAccountNames parsed: {filter_account_names}")

            fb_filtered = fb_enriched
            fb_unmatched_names = []
            logger.info(
                f"DEBUG: filter_account_names = {filter_account_names}, provider_filter = {provider_filter}"
            )
            if filter_account_names and provider_filter == 5:
                logger.info(
                    f"Applying FB filter with {len(filter_account_names)} names"
                )
                logger.info(
                    f"Filter set: {set(name.lower().strip() for name in filter_account_names)}"
                )
                # Debug: show first few account names from the data
                if fb_enriched:
                    sample_names = [item.get("accountName") for item in fb_enriched[:5]]
                    logger.info(f"Sample account names from data: {sample_names}")
                filter_set = set(name.lower().strip() for name in filter_account_names)
                matched_names = set()
                fb_filtered = []
                for item in fb_enriched:
                    account_name = (
                        item.get("accountName") or item.get("targetPageName") or ""
                    )
                    account_name_lower = account_name.lower().strip()
                    if account_name_lower in filter_set:
                        fb_filtered.append(item)
                        matched_names.add(account_name_lower)
                fb_unmatched_names = [
                    name
                    for name in filter_account_names
                    if name.lower().strip() not in matched_names
                ]
                logger.info(
                    f"Filtered to {len(fb_filtered)} Facebook results matching the {len(filter_account_names)} provided account names"
                )

            # Apply filter to Instagram results
            ig_filtered = ig_enriched
            ig_unmatched_names = []

            # NEW: Filter by igContentType (topics vs hashtags)
            ig_content_type = placeholders.get("igContentType", "all").lower()
            logger.info(f"IG Content Type filter: {ig_content_type}")

            # First apply account name filter if provided
            if filter_account_names and provider_filter == 3:
                filter_set = set(name.lower().strip() for name in filter_account_names)
                matched_names = set()
                ig_filtered = []
                for item in ig_enriched:
                    account_name = (
                        item.get("accountName") or item.get("targetPageName") or ""
                    )
                    account_name_lower = account_name.lower().strip()
                    if account_name_lower in filter_set:
                        ig_filtered.append(item)
                        matched_names.add(account_name_lower)
                ig_unmatched_names = [
                    name
                    for name in filter_account_names
                    if name.lower().strip() not in matched_names
                ]
                logger.info(
                    f"Filtered to {len(ig_filtered)} Instagram results matching the {len(filter_account_names)} provided account names"
                )

            # Apply criteriaType filter (topics vs hashtags)
            if ig_content_type != "all" and provider_filter == 3:
                logger.info(f"Applying criteriaType filter: {ig_content_type}")
                if ig_content_type == "topics":
                    # Keep only topics (pages)
                    ig_filtered = [
                        item
                        for item in ig_filtered
                        if item.get("providerSpecific", {}).get("criteriaType")
                        == "topics"
                    ]
                    logger.info(f"Filtered to {len(ig_filtered)} topics (pages) only")
                elif ig_content_type == "hashtags":
                    # Keep only hashtags
                    ig_filtered = [
                        item
                        for item in ig_filtered
                        if item.get("providerSpecific", {}).get("criteriaType")
                        == "hashtags"
                    ]
                    logger.info(f"Filtered to {len(ig_filtered)} hashtags only")

            # Return structure based on filter
            if provider_filter == 5:
                return {
                    "data": fb_filtered,
                    "meta": {
                        "totalAccounts": len(fb_accounts),
                        "totalSubscriptions": len(fb_filtered),
                        "companyId": company_id,
                        "currentCompany": company_info,
                        "userMapping": len(user_map) > 0,
                        "debug_user_count": unique_count,
                        "method": "section31_discovery",
                        "filterApplied": len(filter_account_names) > 0
                        if filter_account_names
                        else False,
                        "unmatchedNames": fb_unmatched_names,
                    },
                }
            elif provider_filter == 3:
                return {
                    "data": ig_filtered,
                    "meta": {
                        "totalAccounts": len(ig_accounts),
                        "totalSubscriptions": len(ig_filtered),
                        "companyId": company_id,
                        "currentCompany": company_info,
                        "userMapping": len(user_map) > 0,
                        "debug_user_count": unique_count,
                        "method": "section31_discovery",
                        "filterApplied": len(filter_account_names) > 0
                        if filter_account_names
                        else False,
                        "unmatchedNames": ig_unmatched_names,
                    },
                }

            return {
                "data": {
                    "facebook": fb_enriched,
                    "instagram": ig_enriched,
                    "summary": {
                        "totalFacebookAccounts": len(fb_accounts),
                        "totalInstagramAccounts": len(ig_accounts),
                        "totalSubscriptions": total_subs,
                    },
                },
                "meta": {
                    "companyId": company_id,
                    "currentCompany": company_info,
                    "userMapping": len(user_map) > 0,
                    "debug_user_count": unique_count,
                    "method": "section31_discovery",
                },
            }

    except Exception as e:
        logger.error(f"Monitored pages handler failed: {e}")
        logger.exception("Full traceback:")
        return {"error": True, "status": 500, "message": str(e)}


async def list_insight_pages_handler(
    token: str, placeholders: Dict[str, str]
) -> Dict[str, Any]:
    """Step 1: Handler for List Explore+ Insight Pages that maps user IDs to names/emails"""
    logger.info("=== LIST INSIGHT PAGES HANDLER START ===")
    import asyncio

    account_id = placeholders.get("accountId") or placeholders.get("companyId")
    if not account_id:
        return {
            "error": True,
            "status": 400,
            "message": "accountId/companyId is required",
        }

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "X-Client-Name": "mi-web-app",
            }

            # 1. Fetch dashboard data and user mapping in parallel
            dash_url = f"https://r4dar-darlyng-prod.meltwater.io/1.0/accounts/{account_id}/insight-pages/search"

            # Support textSearch parameter for filtering insight pages
            text_search = (
                placeholders.get("textSearch")
                or placeholders.get("searchText")
                or placeholders.get("query")
            )

            dash_body: Dict[str, Any] = {
                "workspaceId": None,
                "page": 0,
                "sortBy": "updated",
                "privatePages": False,
                "pagination": {
                    "offset": 0,
                    "count": 25,
                    "sortBy": "updated",
                    "sortOrder": "desc",
                },
            }

            if text_search:
                dash_body["textSearch"] = text_search
                logger.info(f"Filtering insight pages with textSearch: '{text_search}'")
            else:
                dash_body["tab"] = "workspace"
                dash_body["sortBy"] = "title"
                dash_body["sortOrder"] = "asc"
                dash_body["pagination"] = {
                    "offset": 0,
                    "count": 100,
                    "sortBy": "title",
                    "sortOrder": "asc",
                }

            dash_task = client.post(dash_url, json=dash_body, headers=headers)
            user_map_task = get_user_map(token, company_id=account_id)

            dash_resp, user_map_result = await asyncio.gather(dash_task, user_map_task)
            user_map, unique_count = user_map_result

            if dash_resp.status_code != 200:
                return {
                    "error": True,
                    "status": dash_resp.status_code,
                    "message": f"Insight Pages API failed: {dash_resp.text[:200]}",
                }

            data = dash_resp.json()
            results = data.get("data", [])

            # Debug: Check sample author IDs from insight pages
            sample_author_ids = [
                item.get("author") for item in results[:5] if item.get("author")
            ]
            logger.info(f"Sample author IDs from insight pages: {sample_author_ids}")
            if sample_author_ids:
                for aid in sample_author_ids[:3]:
                    if aid in user_map:
                        logger.info(
                            f"  Author {aid}: FOUND in user_map -> {user_map[aid]}"
                        )
                    else:
                        logger.info(f"  Author {aid}: NOT FOUND in user_map")

            # 2. Enrich using deep_enrich for better field placement and robustness
            enriched = [deep_enrich(item, user_map, {}) for item in results]
            enriched = ensure_enrichment_fields(enriched)
            enriched = convert_timestamps(enriched)

            # Debug: Check if enrichment worked on first item
            if enriched and len(enriched) > 0:
                first = enriched[0]
                logger.info(f"First item author field: {first.get('author')}")
                logger.info(f"First item author_Name field: {first.get('author_Name')}")

            # 3. Get current company info
            company_info = await get_current_company_info(token)

            return {
                "data": enriched,
                "meta": {
                    "total": len(enriched),
                    "userMapping": len(user_map) > 0,
                    "companyId": account_id,
                    "currentCompany": company_info,
                    "debug_user_count": unique_count,
                    "debug_sample_mapping": list(user_map.keys())[:20],
                },
            }

    except Exception as e:
        logger.error(f"Insight pages handler failed: {e}")
        return {"error": True, "status": 500, "message": str(e)}


async def list_explore_plus_searches_handler(
    token: str, placeholders: Dict[str, str], run_id: Optional[str] = None
) -> Dict[str, Any]:
    """Handler for List Explore+ Searches with automatic pagination to fetch all results"""
    logger.info("=== LIST EXPLORE+ SEARCHES HANDLER START ===")
    import asyncio
    # Clean token to ensure no double-Bearer prefixing
    token = token.replace("Bearer ", "").replace("bearer ", "").strip()

    company_id = placeholders.get("companyId") or placeholders.get("accountId")
    if not company_id:
        import jwt
        try:
            decoded_token = jwt.decode(token, options={"verify_signature": False})
            company_id = decoded_token.get("company", {}).get("_id") or decoded_token.get("user", {}).get("activeCompanyId")
        except Exception as e:
            logger.error(f"Failed to decode token for companyId: {e}")
            
    if not company_id:
        return {
            "error": True,
            "status": 400,
            "message": "companyId/accountId is required and could not be extracted from token",
        }

    # Get optional filterNames - list of search names to filter by (one per line)
    filter_names_raw = placeholders.get("filterNames") or ""
    filter_names = []
    if filter_names_raw:
        # Split by newlines and clean up
        filter_names = [
            name.strip() for name in filter_names_raw.split("\n") if name.strip()
        ]
        logger.info(f"Filtering by {len(filter_names)} specific search names")

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "X-Client-Name": "mi-web-app",
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.9",
                "Origin": "https://app.meltwater.com",
                "Referer": "https://app.meltwater.com/",
            }

            # Pre-fetch user map for enrichment (parallel with API calls)
            logger.info(
                f"Pre-fetching user map for enrichment (companyId: {company_id})..."
            )
            user_map_task = get_user_map(token, company_id=company_id)

            # Fetch custom workspaces list
            workspaces = []
            try:
                graphql_headers = {
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                    "Accept": "*/*",
                    "ApolloGraphql-Client-Name": "triton-script",
                    "x-company-id": str(company_id)
                }
                graphql_body = {
                    "query": """
                    query GetWorkspace {
                        viewer {
                            company {
                                workspaces {
                                    _id
                                    name
                                    description
                                    created
                                }
                            } 
                        }
                    }
                    """
                }
                logger.info("Fetching custom workspaces list via GraphQL...")
                if run_id:
                    emit_run_event(
                        run_id,
                        "fetch_workspaces",
                        "info",
                        "Fetching custom workspaces list via GraphQL query...",
                        {"companyId": company_id}
                    )
                ws_resp = await client.post(
                    "https://mw-graph.meltwater.io/graphql",
                    json=graphql_body,
                    headers=graphql_headers,
                    timeout=15.0
                )
                if ws_resp.status_code == 200:
                    ws_data = ws_resp.json()
                    ws_list = ws_data.get("data", {}).get("viewer", {}).get("company", {}).get("workspaces", []) or []
                    for ws in ws_list:
                        ws_id = ws.get("_id")
                        ws_name = ws.get("name")
                        if ws_id and ws_name:
                            workspaces.append((ws_id, ws_name))
                    logger.info(f"Discovered {len(workspaces)} custom workspaces")
                    if run_id:
                        emit_run_event(
                            run_id,
                            "fetch_workspaces",
                            "info",
                            f"Successfully discovered {len(workspaces)} custom workspaces: " + ", ".join([w[1] for w in workspaces]),
                            {"workspaces_count": len(workspaces)}
                        )
                else:
                    logger.warning(f"Failed to fetch workspaces list: {ws_resp.status_code}")
                    if run_id:
                        emit_run_event(
                            run_id,
                            "fetch_workspaces",
                            "warning",
                            f"Failed to fetch workspaces list: HTTP {ws_resp.status_code}. Defaulting to Admin Workspace only.",
                            {"status": ws_resp.status_code}
                        )
            except Exception as e:
                logger.warning(f"Error fetching custom workspaces list: {e}")
                if run_id:
                    emit_run_event(
                        run_id,
                        "fetch_workspaces",
                        "warning",
                        f"Error fetching workspaces list: {str(e)}. Defaulting to Admin Workspace only."
                    )

            # Always append the default/Admin Workspace last to act as fallback/catch-all
            workspaces.append((None, "Admin Workspace"))

            # Helper: Port parse_search_clause from Python script
            def parse_search_clause(clause):
                output = {
                    "query_string": "",
                    "case_sensitive": "no",
                    "spam_type": "",
                    "countries": "",
                    "followers_gt": "",
                    "followers_lt": "",
                    "profile_type": "",
                    "languages": "",
                    "platforms": "",
                    "tones": ""
                }

                def extract_from_dict(item):
                    if "meltwaterBoolean" in item:
                        output["query_string"] = item["meltwaterBoolean"].get("query", "")
                        output["case_sensitive"] = item["meltwaterBoolean"].get("caseSensitive", "no")
                    if "spam-type" in item:
                        val = item["spam-type"]
                        output["spam_type"] = ", ".join(val) if isinstance(val, list) else str(val)
                    if "countries" in item:
                        val = item["countries"]
                        output["countries"] = ", ".join(val) if isinstance(val, list) else str(val)
                    if "followers" in item:
                        followers = item["followers"]
                        if isinstance(followers, dict):
                            output["followers_gt"] = str(followers.get("gt", ""))
                            output["followers_lt"] = str(followers.get("lt", ""))
                    if "profileType" in item:
                        val = item["profileType"]
                        output["profile_type"] = ", ".join(val) if isinstance(val, list) else str(val)
                    if "languages" in item:
                        val = item["languages"]
                        output["languages"] = ", ".join(val) if isinstance(val, list) else str(val)
                    if "platforms" in item:
                        val = item["platforms"]
                        output["platforms"] = ", ".join(val) if isinstance(val, list) else str(val)
                    if "tones" in item:
                        val = item["tones"]
                        output["tones"] = ", ".join(val) if isinstance(val, list) else str(val)

                if not clause:
                    return output

                import json
                if isinstance(clause, str):
                    try:
                        clause = json.loads(clause)
                    except json.JSONDecodeError:
                        output["query_string"] = clause
                        return output

                if isinstance(clause, dict):
                    stack = [clause]
                    while stack:
                        current = stack.pop()
                        if isinstance(current, dict):
                            extract_from_dict(current)
                            for value in current.values():
                                if isinstance(value, list):
                                    stack.extend(value)
                                elif isinstance(value, dict):
                                    stack.append(value)
                        elif isinstance(current, list):
                            stack.extend(current)

                return output

            # Helper: Port extract_combined_queries_labels from Python script
            def extract_combined_queries_labels(details):
                combined_ids = ""
                combined_labels = ""

                if details.get("kind") == "Combined":
                    references = details.get("references", {}) or {}
                    query_ids = references.get("queries", []) or []
                    combined_ids = ", ".join(str(qid) for qid in query_ids)

                    label_map = {}
                    combined_info = details.get("combined", {}) or {}
                    must_queries = combined_info.get("must", []) or []
                    must_not_queries = combined_info.get("mustNot", []) or []
                    should_queries = combined_info.get("should", []) or []

                    for q in must_queries + must_not_queries + should_queries:
                        if isinstance(q, dict):
                            qid = q.get("id")
                            label = q.get("label")
                            if qid:
                                label_map[qid] = label

                    combined_labels_list = [str(label_map.get(qid, "Unknown")) for qid in query_ids]
                    combined_labels = ", ".join(combined_labels_list)

                return combined_ids, combined_labels

            all_searches = []
            
            for ws_id, ws_name in workspaces:
                offset = 0
                page_size = 100  # Max allowed by API
                has_more = True
                max_pages = 50  # Safety limit per workspace
                page = 0

                if run_id:
                    emit_run_event(
                        run_id,
                        "fetch_searches",
                        "info",
                        f"Starting paginated search fetch for workspace: '{ws_name}' ({ws_id or 'default'})..."
                    )
                while has_more and page < max_pages:
                    page += 1
                    logger.info(
                        f"Fetching Explore+ searches for workspace '{ws_name}' ({ws_id}) page {page} (offset: {offset}, limit: {page_size})"
                    )

                    search_body = {
                        "showHidden": True,
                        "type": "Query",
                        "tab": "workspace" if ws_id else "account",
                        "textSearch": "",
                        "pagination": {
                            "count": page_size,
                            "offset": offset,
                            "sortOrder": "asc",
                            "sortBy": "label",
                        },
                        "authorLists": [],
                        "workspaceId": ws_id,
                        "additionalFields": ["filter", "searchClause", "groupPath", "combined", "references"]
                    }

                    if ws_id:
                        search_url = f"https://r4dar-darlyng-prod.meltwater.io/1.0/accounts/{company_id}/workspaces/{ws_id}/queries/search"
                    else:
                        search_url = f"https://r4dar-darlyng-prod.meltwater.io/1.0/accounts/{company_id}/queries/search"

                    try:
                        resp = await client.post(
                            search_url, json=search_body, headers=headers, timeout=30.0
                        )

                        if resp.status_code != 200:
                            logger.error(
                                f"Explore+ searches API failed for workspace {ws_name}: {resp.status_code}"
                            )
                            break

                        data = resp.json()
                        searches = data.get("data", [])

                        if not searches:
                            has_more = False
                            break

                        # Process searches: Parse and enrich with workspace info
                        for s in searches:
                            search_clause = s.get("filter", {}).get("searchClause") if s.get("filter") else None
                            parsed = parse_search_clause(search_clause)
                            combined_ids, combined_labels = extract_combined_queries_labels(s)

                            s["workspace"] = ws_id or "Admin Workspace"
                            s["workspace_name"] = ws_name
                            
                            s["query_string"] = parsed["query_string"]
                            s["search_query"] = parsed["query_string"]
                            s["search_caseSensitive"] = parsed["case_sensitive"]
                            s["spam_type"] = parsed["spam_type"]
                            s["countries"] = parsed["countries"]
                            s["followers_gt"] = parsed["followers_gt"]
                            s["followers_lt"] = parsed["followers_lt"]
                            s["profile_type"] = parsed["profile_type"]
                            s["languages"] = parsed["languages"]
                            s["platforms"] = parsed["platforms"]
                            s["tones"] = parsed["tones"]
                            s["combined_ids"] = combined_ids
                            s["combined_labels"] = combined_labels
                            
                            group_path = s.get("groupPath", []) or []
                            gp_id = group_path[0].get("id") if group_path else ""
                            gp_label = group_path[0].get("label") if group_path else ""
                            s["groupPath_id"] = gp_id
                            s["groupPath_label"] = gp_label

                        all_searches.extend(searches)
                        logger.info(f"Fetched {len(searches)} searches for '{ws_name}' on page {page}")
                        if run_id:
                            emit_run_event(
                                run_id,
                                "fetch_searches",
                                "info",
                                f"Fetched page {page} for workspace '{ws_name}' ({len(searches)} searches, total so far: {len(all_searches)})",
                                {"workspace": ws_name, "page": page, "count": len(searches), "total_fetched": len(all_searches)}
                            )

                        if len(searches) < page_size:
                            has_more = False
                        else:
                            offset += page_size

                    except httpx.TimeoutException:
                        logger.error(f"Timeout fetching page {page} for '{ws_name}'")
                        break
                    except Exception as e:
                        logger.error(f"Error fetching page {page} for '{ws_name}': {e}")
                        break

            logger.info(f"Total Explore+ searches fetched before dedup: {len(all_searches)}")

            # Deduplicate searches by ID to handle overlaps across workspaces
            seen_ids = set()
            deduped_searches = []
            for s in all_searches:
                sid = s.get("_id") or s.get("id") or ""
                sid_str = str(sid)
                if sid_str and sid_str not in seen_ids:
                    seen_ids.add(sid_str)
                    deduped_searches.append(s)
                elif not sid_str:
                    deduped_searches.append(s)
            all_searches = deduped_searches
            logger.info(f"Total Explore+ searches after dedup: {len(all_searches)}")
            if run_id:
                emit_run_event(
                    run_id,
                    "fetch_complete",
                    "info",
                    f"Successfully fetched all paginated Explore+ searches. Total: {len(all_searches)} searches across {len(workspaces)} workspaces.",
                    {"total_searches": len(all_searches), "workspaces_count": len(workspaces)}
                )

            # Filter by specific search names if provided
            filtered_searches = all_searches
            unmatched_names = []

            # Debug: Log sample search names from API
            sample_api_names = []
            for search in all_searches[:10]:
                search_name = (
                    search.get("label")
                    or search.get("name")
                    or search.get("searchName")
                    or search.get("queryName")
                    or ""
                )
                sample_api_names.append(search_name)
            logger.info(f"Sample API search names: {sample_api_names}")

            if filter_names:
                # Create a set of lowercase filter names for case-insensitive matching
                filter_set = set(name.lower().strip() for name in filter_names)
                matched_names = set()
                filtered_searches = []
                for search in all_searches:
                    # Check various possible name fields in the search object
                    search_name = (
                        search.get("label")
                        or search.get("name")
                        or search.get("searchName")
                        or search.get("queryName")
                        or ""
                    )
                    search_name_lower = search_name.lower().strip()
                    if search_name_lower in filter_set:
                        filtered_searches.append(search)
                        matched_names.add(search_name_lower)

                # Find unmatched names
                unmatched_names = [
                    name
                    for name in filter_names
                    if name.lower().strip() not in matched_names
                ]
                logger.info(
                    f"Filtered to {len(filtered_searches)} searches matching the {len(filter_names)} provided names"
                )
                logger.info(f"Unmatched names: {len(unmatched_names)}")

            # Filter by date range if provided
            from datetime import datetime
            import dateutil.parser

            def parse_date(date_str_or_num):
                if not date_str_or_num:
                    return None
                if isinstance(date_str_or_num, (int, float)):
                    if date_str_or_num > 9999999999:
                        return datetime.fromtimestamp(date_str_or_num / 1000)
                    return datetime.fromtimestamp(date_str_or_num)
                try:
                    return dateutil.parser.parse(str(date_str_or_num)).replace(tzinfo=None)
                except:
                    return None

            start_date = parse_date(placeholders.get("startDate"))
            end_date = parse_date(placeholders.get("endDate"))

            if start_date or end_date:
                logger.info(f"Filtering Explore+ searches by date: start={start_date}, end={end_date}")
                if run_id:
                    emit_run_event(
                        run_id,
                        "filter_dates",
                        "info",
                        f"Filtering searches by created dates: {start_date or 'Any'} to {end_date or 'Any'}..."
                    )
                date_filtered = []
                for search in filtered_searches:
                    # Explore+ usually uses 'created' or 'createdAt'
                    created_raw = search.get("created") or search.get("createdAt")
                    if not created_raw:
                        # Include items with no date to be safe
                        date_filtered.append(search)
                        continue
                        
                    created_dt = parse_date(created_raw)
                    if not created_dt:
                        date_filtered.append(search)
                        continue
                        
                    include = True
                    if start_date and created_dt < start_date:
                        include = False
                    if end_date and created_dt > end_date:
                        include = False
                        
                    if include:
                        date_filtered.append(search)
                
                filtered_searches = date_filtered
                logger.info(f"Filtered to {len(filtered_searches)} searches within date range")
                if run_id:
                    emit_run_event(
                        run_id,
                        "filter_dates",
                        "info",
                        f"Date filtering complete: kept {len(filtered_searches)} out of {len(all_searches)} searches."
                    )

            # Wait for user_map and enrich results
            user_map_result = await user_map_task
            user_map, unique_count = user_map_result

            # Enrich filtered searches with user data
            logger.info(
                f"Enriching {len(filtered_searches)} searches with user_map({len(user_map)}) using companyId: {company_id}"
            )
            if run_id:
                emit_run_event(
                    run_id,
                    "enrich_users",
                    "info",
                    f"Enriching creator/modifier details and user permissions/roles for {len(filtered_searches)} searches...",
                    {"searches_count": len(filtered_searches), "cached_users_count": len(user_map)}
                )
            enriched_searches = [
                deep_enrich(item, user_map, {}) for item in filtered_searches
            ]
            enriched_searches = ensure_enrichment_fields(enriched_searches)
            enriched_searches = convert_timestamps(enriched_searches)

            # Get current company info for metadata
            company_info = await get_current_company_info(token)

            return {
                "data": enriched_searches,
                "meta": {
                    "total": len(enriched_searches),
                    "totalBeforeFilter": len(all_searches) if filter_names else None,
                    "filterNamesCount": len(filter_names) if filter_names else None,
                    "matchedCount": len(enriched_searches) if filter_names else None,
                    "unmatchedCount": len(unmatched_names) if filter_names else None,
                    "unmatchedNames": unmatched_names[:50]
                    if unmatched_names
                    else None,  # Limit to first 50
                    "sampleApiNames": sample_api_names[
                        :20
                    ],  # Show what names look like in API
                    "companyId": company_id,
                    "currentCompany": company_info,
                    "userMapping": len(user_map) > 0,
                    "debug_user_count": unique_count,
                    "debug_sample_mapping": list(user_map.keys())[:20],
                    "pagesFetched": page,
                    "textSearch": placeholders.get("textSearch"),
                },
            }

    except Exception as e:
        logger.error(f"Explore+ searches handler failed: {e}")
        logger.exception("Full exception:")
        return {"error": True, "status": 500, "message": str(e)}


async def list_monitor_views_handler(
    token: str, placeholders: Dict[str, str]
) -> Dict[str, Any]:
    """Step 2: Handler for List Monitor Views that maps user and search IDs"""
    logger.info("=== LIST MONITOR VIEWS HANDLER START ===")
    import asyncio

    company_id = placeholders.get("companyId") or placeholders.get("accountId")
    if not company_id:
        return {"error": True, "status": 400, "message": "companyId is required"}

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "X-Client-Name": "mi-web-app",
            }

            # 1. Fetch data in parallel
            # Correct URL using app.meltwater.com/api proxy to avoid DNS issues
            mon_url = f"https://app.meltwater.com/api/mi-monitor-bff-v2/prd/monitors?includeFavoritesInfo=true&includeDraft=true"

            mon_task = client.get(mon_url, headers=headers)
            user_map_task = get_user_map(token, company_id=company_id)
            search_map_task = get_search_map(token, company_id=company_id)

            mon_resp, user_map_result, search_map = await asyncio.gather(
                mon_task, user_map_task, search_map_task
            )
            user_map, unique_count = user_map_result

            if mon_resp.status_code != 200:
                return {
                    "error": True,
                    "status": mon_resp.status_code,
                    "message": f"Monitor API failed: {mon_resp.text[:200]}",
                }

            results = mon_resp.json()

            # 2. Enrich using deep_enrich
            logger.info(
                f"Enriching {len(results)} monitors with user_map({len(user_map)}) and search_map({len(search_map)}) using companyId: {company_id}"
            )
            enriched = [deep_enrich(item, user_map, search_map) for item in results]
            enriched = ensure_enrichment_fields(enriched)
            enriched = convert_timestamps(enriched)

            # Debug: Check if enrichment worked
            if enriched and len(enriched) > 0:
                first = enriched[0]
                logger.info(f"First item createdBy field: {first.get('createdBy')}")
                logger.info(
                    f"First item createdBy_Name field: {first.get('createdBy_Name')}"
                )
                logger.info(
                    f"First item createdBy_Email field: {first.get('createdBy_Email')}"
                )

            return {
                "data": enriched,
                "meta": {
                    "total": len(enriched),
                    "userMapping": len(user_map) > 0,
                    "companyId": company_id,
                    "debug_user_count": unique_count,
                },
            }

    except Exception as e:
        logger.error(f"List analyze dashboards handler failed: {e}")
        logger.exception("Full exception details:")
        return {"error": True, "status": 500, "message": str(e)}


async def list_alerts_handler(
    token: str, placeholders: Dict[str, str] = None
) -> Dict[str, Any]:
    """
    Fetches all alerts/subscriptions with user and search data enrichment.
    Two-step flow:
      1. GET /v2/subscriptions/count — get counts per alert type
      2. GET /v2/subscriptions?types=<comma-separated-non-zero-types> — fetch actual alerts
    Maps user IDs to names/emails and query IDs to search names.
    """
    logger.info("=== LIST ALERTS HANDLER START ===")
    import asyncio
    import jwt

    try:
        if not token:
            return {"error": True, "status": 400, "message": "Token is required"}

        token = token.replace("Bearer ", "").replace("bearer ", "").strip()

        try:
            decoded_token = jwt.decode(token, options={"verify_signature": False})
            company_id = decoded_token.get("company", {}).get("_id") or decoded_token.get("user", {}).get("activeCompanyId")
        except Exception as e:
            return {"error": True, "status": 400, "message": f"Could not extract companyId: {str(e)}"}

        if not company_id:
            return {"error": True, "status": 400, "message": "companyId is required"}

        sas_headers = {
            "Authorization": token,
            "Accept": "*/*",
            "Content-Type": "application/json",
            "Origin": "https://app.meltwater.com",
            "Referer": "https://app.meltwater.com/",
            "x-client-name": "mi-web-app_smart-alerts",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
        }

        async with httpx.AsyncClient(timeout=60.0) as client:
            # Step 1: Fetch subscription counts per type
            count_url = "https://sas-web-api.notifications.meltwater.com/v2/subscriptions/count"
            logger.info("Step 1: Fetching alert subscription counts...")

            count_resp = await client.get(count_url, headers=sas_headers)
            if count_resp.status_code != 200:
                return {"error": True, "status": count_resp.status_code, "message": f"Alerts count API failed: {count_resp.text[:200]}"}

            count_data = count_resp.json()
            logger.info(f"Alert counts response: {count_data}")

            active_types = [key for key, val in count_data.items() if isinstance(val, (int, float)) and val > 0]
            logger.info(f"Active alert types (count > 0): {active_types}")

            if not active_types:
                return {
                    "data": [],
                    "meta": {"totalCount": 0, "companyId": company_id, "alertTypeCounts": count_data, "activeTypes": []},
                }

            # Step 2: Fetch actual subscriptions for active types
            types_param = ",".join(active_types)
            subs_url = f"https://sas-web-api.notifications.meltwater.com/v2/subscriptions?types={types_param}"
            logger.info(f"Step 2: Fetching subscriptions for types: {types_param}")

            subs_resp = await client.get(subs_url, headers=sas_headers)
            if subs_resp.status_code != 200:
                return {"error": True, "status": subs_resp.status_code, "message": f"Alerts subscriptions API failed: {subs_resp.text[:200]}"}

            subscriptions_data = subs_resp.json()
            if isinstance(subscriptions_data, dict):
                subscriptions = subscriptions_data.get("data") or subscriptions_data.get("subscriptions") or subscriptions_data.get("items") or []
            elif isinstance(subscriptions_data, list):
                subscriptions = subscriptions_data
            else:
                subscriptions = []

            logger.info(f"Fetched {len(subscriptions)} subscriptions")

            # Enrich with user/search maps
            user_map_task = get_user_map(token, company_id=company_id)
            search_map_task = get_search_map(token, company_id=company_id)
            user_map_result, search_map = await asyncio.gather(user_map_task, search_map_task)
            user_map, unique_count = user_map_result

            enriched_alerts = [deep_enrich(item, user_map, search_map) for item in subscriptions]

            # Array-based enrichment with ordered field placement
            ordered_alerts = []
            for item in enriched_alerts:
                new_item = {}
                for k, v in item.items():
                    new_item[k] = v
                    if k == "user_ids" and isinstance(v, list):
                        new_item["userNames"] = [user_map.get(uid, {}).get("name", uid) for uid in v]
                        new_item["userEmails"] = [user_map.get(uid, {}).get("email", "") for uid in v]
                    elif k == "query_ids" and isinstance(v, list):
                        new_item["queryNames"] = [search_map.get(str(qid), str(qid)) for qid in v]
                ordered_alerts.append(new_item)
            enriched_alerts = ordered_alerts

            enriched_alerts = ensure_enrichment_fields(enriched_alerts)
            enriched_alerts = convert_timestamps(enriched_alerts)

            return {
                "data": enriched_alerts,
                "meta": {
                    "totalCount": len(enriched_alerts),
                    "companyId": company_id,
                    "alertTypeCounts": count_data,
                    "activeTypes": active_types,
                    "userMapping": len(user_map) > 0,
                    "searchMapping": len(search_map) > 0,
                },
            }

    except Exception as e:
        logger.error(f"List alerts handler failed: {e}")
        logger.exception("Full exception details:")
        return {"error": True, "status": 500, "message": f"List alerts handler failed: {str(e)}"}


async def list_digest_reports_handler(
    token: str, placeholders: Dict[str, str] = None
) -> Dict[str, Any]:
    """
    Fetches all digest report definitions with user data enrichment.
    Enriches createdUserId with _Name and _Email fields.
    """
    logger.info("=== LIST DIGEST REPORTS HANDLER START ===")
    import asyncio
    import jwt

    try:
        if not token:
            return {"error": True, "status": 400, "message": "Token is required"}

        token = token.replace("Bearer ", "").replace("bearer ", "").strip()

        try:
            decoded_token = jwt.decode(token, options={"verify_signature": False})
            company_id = decoded_token.get("company", {}).get("_id") or decoded_token.get("user", {}).get("activeCompanyId")
        except Exception as e:
            return {"error": True, "status": 400, "message": f"Could not extract companyId: {str(e)}"}

        if not company_id:
            return {"error": True, "status": 400, "message": "companyId is required"}

        sas_headers = {
            "Authorization": token,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Content-Type": "application/json",
            "Origin": "https://app.meltwater.com",
            "Referer": "https://app.meltwater.com/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "cross-site",
        }

        async with httpx.AsyncClient(timeout=60.0) as client:
            # Fetch report definitions
            reports_url = "https://dashboard-services.daily-digest.meltwater.io/dashboard_services/v2/reportDefinitions/"
            logger.info("Fetching digest report definitions...")

            reports_resp = await client.get(reports_url, headers=sas_headers)
            if reports_resp.status_code != 200:
                return {"error": True, "status": reports_resp.status_code, "message": f"Digest reports API failed: {reports_resp.text[:200]}"}

            reports_data = reports_resp.json()
            if isinstance(reports_data, dict):
                reports = reports_data.get("data") or reports_data.get("reports") or reports_data.get("items") or []
            elif isinstance(reports_data, list):
                reports = reports_data
            else:
                reports = []

            logger.info(f"Fetched {len(reports)} digest reports")

            # Fetch user map for enrichment
            user_map_task = get_user_map(token, company_id=company_id)
            user_map_result = await user_map_task
            user_map, unique_count = user_map_result

            # Enrich with deep_enrich first
            enriched_reports = [deep_enrich(item, user_map, {}) for item in reports]

            # Ordered enrichment for createdUserId
            ordered_reports = []
            for item in enriched_reports:
                new_item = {}
                for k, v in item.items():
                    new_item[k] = v
                    if k == "createdUserId" and isinstance(v, str):
                        info = user_map.get(v, {})
                        new_item["createdUserId_Name"] = info.get("name", v)
                        new_item["createdUserId_Email"] = info.get("email", "")
                ordered_reports.append(new_item)
            enriched_reports = ordered_reports

            # Flatten recipients array into CSV-friendly string
            for item in enriched_reports:
                recipients = item.get("recipients", [])
                if isinstance(recipients, list) and len(recipients) > 0:
                    recipient_parts = []
                    for r in recipients:
                        name = r.get("userId_Name") or r.get("name", "")
                        email = r.get("userId_Email") or r.get("email", "")
                        if name and email:
                            recipient_parts.append(f"{name} ({email})")
                        elif email:
                            recipient_parts.append(email)
                        elif name:
                            recipient_parts.append(name)
                    item["recipients"] = "; ".join(recipient_parts)
                    item["recipients_count"] = len(recipients)

            enriched_reports = ensure_enrichment_fields(enriched_reports)
            enriched_reports = convert_timestamps(enriched_reports)

            return {
                "data": enriched_reports,
                "meta": {
                    "totalCount": len(enriched_reports),
                    "companyId": company_id,
                    "userMapping": len(user_map) > 0,
                },
            }

    except Exception as e:
        logger.error(f"List digest reports handler failed: {e}")
        logger.exception("Full exception details:")
        return {"error": True, "status": 500, "message": f"List digest reports handler failed: {str(e)}"}


async def list_automations_handler(
    token: str, placeholders: Dict[str, str] = None
) -> Dict[str, Any]:
    """
    Fetches all automation rules for the company with user data enrichment.
    Uses the automation API to list all rules, then enriches createdBy/updatedBy with names and emails.
    """
    logger.info("=== LIST AUTOMATIONS HANDLER START ===")
    import asyncio
    import jwt

    try:
        if not token:
            return {
                "error": True,
                "status": 400,
                "message": "Token is required",
            }

        # Extract companyId from token
        try:
            decoded_token = jwt.decode(token, options={"verify_signature": False})
            company_id = decoded_token.get("company", {}).get("_id") or decoded_token.get("user", {}).get("activeCompanyId")
        except Exception as e:
            return {
                "error": True,
                "status": 400,
                "message": f"Could not extract companyId: {str(e)}",
            }

        if not company_id:
            return {
                "error": True,
                "status": 400,
                "message": "companyId is required",
            }

        async with httpx.AsyncClient(timeout=60.0) as client:
            headers = {
                "Authorization": f"{token}",  # Send JWT directly (no "Bearer " prefix)
                "Accept": "*/*",
                "Content-Type": "application/json",
            }

            # Fetch automation rules
            rules_url = f"https://app.meltwater.com/api/automation/v1/rules?companyId={company_id}"
            
            # Fetch user map and search map in parallel
            user_map_task = get_user_map(token, company_id=company_id)
            search_map_task = get_search_map(token, company_id=company_id)

            rules_resp, user_map_result, search_map = await asyncio.gather(
                client.get(rules_url, headers=headers),
                user_map_task,
                search_map_task
            )
            user_map, unique_count = user_map_result

            if rules_resp.status_code != 200:
                return {
                    "error": True,
                    "status": rules_resp.status_code,
                    "message": f"Automation API failed: {rules_resp.text[:200]}",
                }

            rules = rules_resp.json()
            if isinstance(rules, dict):
                rules = rules.get("data") or rules.get("rules") or []
            
            # Enrich rules with user and search data
            logger.info(
                f"Enriching {len(rules)} automation rules with user_map({len(user_map)}) and search_map({len(search_map)})"
            )
            enriched_rules = [deep_enrich(rule, user_map, search_map) for rule in rules]
            enriched_rules = ensure_enrichment_fields(enriched_rules)
            enriched_rules = convert_timestamps(enriched_rules)

            return {
                "data": enriched_rules,
                "meta": {
                    "totalCount": len(enriched_rules),
                    "companyId": company_id,
                    "userMapping": len(user_map) > 0,
                    "searchMapping": len(search_map) > 0,
                },
            }

    except Exception as e:
        logger.error(f"List automations request failed: {e}")
        logger.exception("Full exception details:")
        return {
            "error": True,
            "status": 500,
            "message": f"List automations request failed: {str(e)}",
        }


async def list_analyze_dashboards_handler(token: str) -> Dict[str, Any]:
    """
    Handler for List Analyze Dashboards (Analyze -> Dashboards).
    Fetches dashboards from ua-dashboard-api and enriches with user data.
    """
    logger.info("=== LIST ANALYZE DASHBOARDS HANDLER START ===")
    import jwt

    try:
        if not token:
            return {
                "error": True,
                "status": 400,
                "message": "Token is required",
            }

        # Extract companyId from token
        try:
            decoded_token = jwt.decode(token, options={"verify_signature": False})
            company_id = decoded_token.get("company", {}).get("_id") or decoded_token.get("user", {}).get("activeCompanyId")
        except Exception as e:
            return {
                "error": True,
                "status": 400,
                "message": f"Could not extract companyId: {str(e)}",
            }

        if not company_id:
            return {
                "error": True,
                "status": 400,
                "message": "companyId is required",
            }

        async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as client:
            # Note: rawAuth: true in preset sends token directly (no "Bearer " prefix)
            # Headers EXACTLY matching working cURL command from browser
            dash_headers = {
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.9",
                "Authorization": token,  # rawAuth: true - no Bearer prefix, capitalized header to match cURL
                "Connection": "keep-alive",
                "Content-Type": "application/json",
                "Origin": "https://app.meltwater.com",
                "Referer": "https://app.meltwater.com/",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "cross-site",
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
                "sec-ch-ua": '"Google Chrome";v="147", "Not.A/Brand";v="8", "Chromium";v="147"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"macOS"',
            }
            
            # Fetch user map in parallel (uses Bearer token for other APIs)
            user_map_task = get_user_map(token, company_id=company_id)
            
            # Fetch dashboards - correct endpoint from working curl command
            dash_url = "https://ua-dashboard-api.meltwater.io/homepage/dashboards"
            dash_resp = await client.get(dash_url, headers=dash_headers)
            user_map_result = await user_map_task
            user_map, unique_count = user_map_result

            if dash_resp.status_code != 200:
                return {
                    "error": True,
                    "status": dash_resp.status_code,
                    "message": f"Analyze Dashboards API failed: {dash_resp.text[:200]}",
                    "data": None,
                }

            # Parse response and flatten for CSV output
            raw_data = dash_resp.json()
            
            # Navigate the nested structure: raw_data -> "data" -> "allDashboards"
            # API returns: { "statusCode": 200, "data": { "lastViewedDashboards": [...], "allDashboards": [...] } }
            
            dashboards = []
            
            # Extract the inner data object
            if isinstance(raw_data, dict):
                inner_data = raw_data.get("data", {})
                
                if isinstance(inner_data, dict):
                    # Extract only allDashboards, discard lastViewedDashboards
                    dashboards = inner_data.get("allDashboards", [])
                    
                    if not isinstance(dashboards, list):
                        logger.warning(f"allDashboards is not a list: {type(dashboards)}")
                        dashboards = []
                    
                    logger.info(f"Extracted {len(dashboards)} dashboards from allDashboards (ignoring lastViewedDashboards)")
                else:
                    logger.warning(f"inner data is not a dict: {type(inner_data)}")
            else:
                logger.warning(f"raw_data is not a dict: {type(raw_data)}")

            # Enrich dashboards with user data (createdBy -> Name/Email)
            if dashboards:
                logger.info(f"Enriching {len(dashboards)} dashboards with user_map")
                enriched = [deep_enrich(item, user_map, {}) for item in dashboards]
                enriched = ensure_enrichment_fields(enriched)
                enriched = convert_timestamps(enriched)
            else:
                enriched = []
                logger.warning("No dashboards to enrich")

            return {
                "data": enriched,
                "meta": {
                    "total": len(enriched),
                    "userMapping": len(user_map) > 0,
                    "companyId": company_id,
                    "debug_user_count": unique_count,
                },
            }

    except Exception as e:
        logger.error(f"List analyze dashboards handler failed: {e}")
        logger.exception("Full exception details:")
        return {"error": True, "status": 500, "message": str(e)}


async def list_added_content_handler(
    token: str,
    placeholders: Dict[str, Any] = None,
    page_size: int = 100,
) -> Dict[str, Any]:
    """
    Handler for List Added Content.
    Paginates through the Added Content GraphQL API to fetch ALL documents
    between startDate and endDate. Handles 100+ results via automatic pagination.
    """
    logger.info("=== LIST ADDED CONTENT HANDLER START ===")
    placeholders = placeholders or {}

    # Extract and validate required date parameters
    start_date = placeholders.get("startDate", "")
    end_date = placeholders.get("endDate", "")

    if not start_date or not end_date:
        return {
            "error": True,
            "status": 400,
            "message": "startDate and endDate are required for Added Content pagination",
            "data": None,
        }

    # Optional filters
    filter_terms = placeholders.get("filterTerms", [])
    filter_tags = placeholders.get("filterTags", [])

    # Handle filterTerms/filterTags as strings (one per line) or lists
    if isinstance(filter_terms, str):
        filter_terms = [
            t.strip() for t in filter_terms.split("\n") if t.strip()
        ] if filter_terms else []
    if isinstance(filter_tags, str):
        filter_tags = [
            t.strip() for t in filter_tags.split("\n") if t.strip()
        ] if filter_tags else []

    # Headers matching working cURL from browser
    headers = {
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Origin": "https://app.meltwater.com",
        "Priority": "u=1, i",
        "Referer": "https://app.meltwater.com/",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "cross-site",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
        "sec-ch-ua": '"Google Chrome";v="147", "Not.A/Brand";v="8", "Chromium";v="147"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"macOS\"",
    }

    # REST API endpoint (not GraphQL)
    api_url = "https://add-content-bff.prod.added-content.meltwater.io/get-company-documents"

    all_documents = []
    page = 0
    total_count = 0

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            while True:
                # REST API request body - use offset-based pagination (matching platform UI)
                # Platform uses page: 10, 20, 30... which translates to offsets: 100, 200, 300...
                # So we use page * pageSize for offset-based pagination
                request_body = {
                    "startDate": start_date,
                    "endDate": end_date,
                    "page": page * page_size,  # Offset-based: 0, 100, 200, 300...
                    "pageSize": page_size,
                    "filterTerms": filter_terms,
                    "filterTags": filter_tags,
                }

                logger.info(
                    f"Fetching Added Content offset {page * page_size} (page {page}, pageSize {page_size})"
                )

                resp = await client.post(
                    api_url,
                    json=request_body,
                    headers=headers,
                    timeout=60.0,
                )

                if resp.status_code != 200:
                    return {
                        "error": True,
                        "status": resp.status_code,
                        "message": f"Added Content API failed on page {page}: {resp.text[:300]}",
                        "data": None,
                    }

                # REST API response parsing
                response_data = resp.json()
                
                if page == 0:
                    total_count = response_data.get("count", 0)
                    logger.info(
                        f"Total documents available: {total_count}"
                    )

                documents = response_data.get("documents", [])

                if not documents:
                    logger.info(f"No more documents at page {page}, stopping.")
                    break

                all_documents.extend(documents)
                logger.info(
                    f"Page {page}: fetched {len(documents)} documents (total so far: {len(all_documents)})"
                )

                # Debug: log date range of fetched documents
                if documents:
                    dates = [d.get("date") for d in documents if d.get("date")]
                    logger.info(f"  Document dates in this batch: {dates[0] if dates else 'unknown'} to {dates[-1] if dates else 'unknown'}")

                # Stop conditions:
                # 1. We've fetched all documents according to the total count
                if total_count > 0 and len(all_documents) >= total_count:
                    logger.info(f"Reached total count ({total_count}), stopping.")
                    break

                # 2. Got fewer documents than pageSize (last page)
                if len(documents) < page_size:
                    logger.info(f"Got {len(documents)} documents (less than pageSize {page_size}), stopping.")
                    break

                page += 1

                # Safety stop to avoid infinite loops
                if page > 1000:
                    logger.warning(
                        "Safety stop: exceeded 1000 pages"
                    )
                    break

        logger.info(
            f"=== LIST ADDED CONTENT COMPLETE: {len(all_documents)} documents fetched ==="
        )

        # Post-process: sort by date (newest first) and filter by exact date range
        from datetime import datetime

        def parse_date(date_str):
            if not date_str:
                return None
            try:
                return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            except:
                try:
                    return datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S.%fZ')
                except:
                    return None

        # Parse the requested date range
        start_dt = parse_date(start_date)
        end_dt = parse_date(end_date)

        # Filter by date range (since API might not respect full range)
        filtered_documents = []
        if start_dt and end_dt:
            for doc in all_documents:
                doc_date_str = doc.get("date")
                if doc_date_str:
                    doc_dt = parse_date(doc_date_str)
                    if doc_dt and start_dt <= doc_dt <= end_dt:
                        filtered_documents.append(doc)
                # Keep documents without date field (defensive)
                else:
                    filtered_documents.append(doc)
            
            logger.info(f"Filtered by date range: {len(all_documents)} -> {len(filtered_documents)} documents")
        else:
            filtered_documents = all_documents

        # Sort by date (newest first / descending)
        filtered_documents.sort(
            key=lambda x: parse_date(x.get("date")) or datetime.min, 
            reverse=True
        )

        # Also sort the original all_documents for meta tracking
        all_documents.sort(
            key=lambda x: parse_date(x.get("date")) or datetime.min, 
            reverse=True
        )

        logger.info(f"Sorted {len(filtered_documents)} documents by date (newest first)")

        return {
            "data": filtered_documents,
            "meta": {
                "total": len(filtered_documents),
                "fetched": len(all_documents),
                "pages": page + 1,
                "startDate": start_date,
                "endDate": end_date,
            },
            "error": False,
        }

    except Exception as e:
        logger.error(f"List Added Content handler failed: {e}")
        logger.exception("Full exception details:")
        return {"error": True, "status": 500, "message": str(e)}


async def list_gail_prompts_handler(token: str) -> Dict[str, Any]:
    """
    Fetches all GAIL prompts by paginating through the GraphQL endpoint.
    """
    url = "https://mw-graph.meltwater.io/graphql"
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
        "Origin": "https://app.meltwater.com",
        "Referer": "https://app.meltwater.com/",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
        "apollographql-client-name": "genai-lens",
        "sec-ch-ua": '"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"macOS"',
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "cross-site",
    }
    
    query = """query GetPaginatedPrompts($filters: PromptFiltersInput, $first: Int, $after: String, $sort: PromptSortInput) {
  getPaginatedPrompts(
    filters: $filters
    first: $first
    after: $after
    sort: $sort
  ) {
    totalCount
    pageInfo {
      endCursor
      hasNextPage
      hasPreviousPage
      startCursor
      __typename
    }
    edges {
      node {
        name
        promptText
        createdAt
        labels {
          id
          name
          __typename
        }
        folder {
          name
          __typename
        }
        createdByUser {
          fullName
          __typename
        }
        geoConfig {
          countryName
          __typename
        }
        id
        __typename
      }
      __typename
    }
    __typename
  }
}"""

    all_prompts = []
    has_next_page = True
    after_cursor = None
    page = 1
    
    async with httpx.AsyncClient(timeout=60.0) as client:
        while has_next_page:
            logger.info(f"Fetching GAIL prompts page {page}...")
            variables = {
                "filters": {"labelIds": []},
                "first": 100,
            }
            if after_cursor:
                variables["after"] = after_cursor
                
            body = {
                "operationName": "GetPaginatedPrompts",
                "variables": variables,
                "query": query
            }
            
            try:
                resp = await client.post(url, json=body, headers=headers)
                
                if resp.status_code >= 400:
                    logger.error(f"GAIL Prompts request failed: {resp.status_code}")
                    return {
                        "error": True,
                        "status": resp.status_code,
                        "message": "Failed to fetch GAIL prompts",
                        "data": all_prompts if all_prompts else None
                    }
                    
                data = resp.json()
                
                if "errors" in data:
                    logger.error(f"GraphQL errors: {data['errors']}")
                    return {
                        "error": True,
                        "status": 400,
                        "message": "GraphQL errors in GAIL Prompts request",
                        "data": all_prompts if all_prompts else data
                    }
                    
                paginated_data = data.get("data", {}).get("getPaginatedPrompts", {})
                edges = paginated_data.get("edges", [])
                page_info = paginated_data.get("pageInfo", {})
                
                for edge in edges:
                    node = edge.get("node", {})
                    # Flatten the structure slightly for CSV export
                    if "createdByUser" in node and isinstance(node["createdByUser"], dict):
                        node["createdByFullName"] = node["createdByUser"].get("fullName")
                    if "folder" in node and isinstance(node["folder"], dict):
                        node["folderName"] = node["folder"].get("name")
                    if "geoConfig" in node and isinstance(node["geoConfig"], dict):
                        node["countryName"] = node["geoConfig"].get("countryName")
                        
                    # Flatten labels to a comma-separated string
                    if "labels" in node and isinstance(node["labels"], list):
                        node["labelNames"] = ", ".join([lbl.get("name", "") for lbl in node["labels"]])
                        
                    all_prompts.append(node)
                    
                has_next_page = page_info.get("hasNextPage", False)
                after_cursor = page_info.get("endCursor")
                
                logger.info(f"Page {page} complete. Fetched {len(edges)} prompts. Total so far: {len(all_prompts)}. Has next page: {has_next_page}")
                page += 1
                
            except Exception as e:
                logger.error(f"Error fetching GAIL prompts: {e}")
                return {
                    "error": True,
                    "status": 500,
                    "message": f"Error fetching GAIL prompts: {str(e)}",
                    "data": all_prompts if all_prompts else None
                }
                
    return {
        "data": all_prompts,
        "meta": {
            "totalCount": len(all_prompts),
            "pagesFetched": page - 1
        }
    }


@router.post("/execute")
async def execute_discovery_request(payload: DiscoveryRequest):
    """
    Generalized proxy for Discovery tool - supports both GraphQL and REST APIs.
    Handles header spoofing, placeholder replacement, and multiple endpoints.
    Also supports composite presets for multi-step operations.
    """

    logger.info(f"=== DISCOVERY REQUEST START ===")
    logger.info(f"Received payload: {payload.dict()}")

    # ── Run Events: Start ──
    handler_name = (payload.composite or {}).get("handler", "direct")
    run_id = start_run(preset_name=handler_name, run_id=payload.run_id)
    emit_run_event(
        run_id,
        "validate_payload",
        "info",
        "Payload received and validated",
        {
            "method": payload.method,
            "endpoint": payload.endpoint or "(composite)",
            "handler": handler_name,
        },
    )

    try:
        # Check if this is a composite preset
        if payload.composite and payload.composite.get("handler"):
            handler_name = payload.composite["handler"]
            logger.info(f"Executing composite handler: {handler_name}")
            emit_run_event(
                run_id,
                "prepare_request",
                "info",
                f"Routing to composite handler: {handler_name}",
            )

            result = None
            if handler_name == "searchUsageHandler":
                result = await search_usage_handler(
                    payload.token, payload.placeholders or {}
                )
            elif handler_name == "listUsersCompleteHandler":
                result = await list_users_complete_handler(payload.token)
            elif handler_name == "listInsightPagesHandler":
                result = await list_insight_pages_handler(
                    payload.token, payload.placeholders or {}
                )
            elif handler_name == "listExplorePlusSearchesHandler":
                result = await list_explore_plus_searches_handler(
                    payload.token, payload.placeholders or {}  , run_id=run_id
                )
            elif handler_name == "listSearchesHandler":
                result = await list_searches_handler(
                    payload.token, payload.placeholders or {}
                )
            elif handler_name == "listMonitorViewsHandler":
                result = await list_monitor_views_handler(
                    payload.token, payload.placeholders or {}
                )
            elif handler_name == "listGailPromptsHandler":
                result = await list_gail_prompts_handler(payload.token)
            elif handler_name == "monitoredFacebookPagesHandler":
                result = await monitored_pages_handler(
                    payload.token, payload.placeholders or {}, provider_filter=5
                )
            elif handler_name == "monitoredInstagramPagesHandler":
                result = await monitored_pages_handler(
                    payload.token, payload.placeholders or {}, provider_filter=3
                )
            elif handler_name == "monitoredPagesHandler":
                result = await monitored_pages_handler(
                    payload.token, payload.placeholders or {}
                )
            elif handler_name == "unifiedAccountDiscoveryHandler":
                result = await unified_account_discovery_handler(
                    payload.token, payload.placeholders or {}
                )
            elif handler_name == "getIdentityHandler":
                result = await get_identity_handler(payload.token)
            elif handler_name == "authorListsHandler":
                result = await author_lists_handler(
                    payload.token, payload.placeholders or {}
                )
            elif handler_name == "listAlertsHandler":
                result = await list_alerts_handler(
                    payload.token, payload.placeholders or {}
                )
            elif handler_name == "listDigestReportsHandler":
                result = await list_digest_reports_handler(
                    payload.token, payload.placeholders or {}
                )
            elif handler_name == "listFilterSetsHandler":
                result = await list_filter_sets_handler(
                    payload.token, payload.placeholders or {}
                )
            elif handler_name == "listExplorePlusCustomFieldsHandler":
                result = await list_explore_plus_custom_fields_handler(
                    payload.token, payload.placeholders or {}
                )
            elif handler_name == "listAutomationsHandler":
                result = await list_automations_handler(
                    payload.token, payload.placeholders or {}
                )
            elif handler_name == "listAnalyzeDashboardsHandler":
                result = await list_analyze_dashboards_handler(payload.token)
            elif handler_name == "listAddedContentHandler":
                result = await list_added_content_handler(
                    payload.token, payload.placeholders or {}
                )
            else:
                emit_run_event(
                    run_id,
                    "execute_upstream",
                    "error",
                    f"Unknown composite handler: {handler_name}",
                )
                finish_run(
                    run_id, "failed", {"error": f"Unknown handler: {handler_name}"}
                )
                return {
                    "error": True,
                    "status": 400,
                    "message": f"Unknown composite handler: {handler_name}",
                    "data": None,
                    "run_id": run_id,
                }

            # Composite handler completed — emit finalize event
            if result is not None:
                is_error = isinstance(result, dict) and result.get("error")
                item_count = 0
                if isinstance(result, dict) and isinstance(result.get("data"), list):
                    item_count = len(result["data"])
                if is_error:
                    emit_run_event(
                        run_id,
                        "finalize",
                        "error",
                        f"Composite handler returned error: {result.get('message', 'unknown')}",
                    )
                    finish_run(
                        run_id, "failed", {"upstream_status": result.get("status")}
                    )
                else:
                    emit_run_event(
                        run_id,
                        "finalize",
                        "success",
                        f"Composite handler completed — {item_count} items returned",
                        {"item_count": item_count},
                    )
                    finish_run(run_id, "completed", {"item_count": item_count})
                # Inject run_id into response
                if isinstance(result, dict):
                    result["run_id"] = run_id
                return result

        # Replace placeholders in endpoint (e.g., {accountId})
        endpoint = payload.endpoint
        if payload.placeholders:
            for key, value in payload.placeholders.items():
                endpoint = endpoint.replace(f"{{{key}}}", value)

        # Construct full URL
        full_url = f"{payload.baseUrl.rstrip('/')}/{endpoint.lstrip('/')}"

        # Build headers - merge custom headers with defaults
        # Handle raw token for specific endpoints like newsfeeds
        auth_header = (
            f"Bearer {payload.token}" if not payload.rawAuth else payload.token
        )
        auth_header_key = "authorization" if payload.rawAuth else "Authorization"

        default_headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
            "Origin": "https://app.meltwater.com",
            "Referer": "https://app.meltwater.com/",
            "Content-Type": "application/json",
            auth_header_key: auth_header,
            "sec-ch-ua": '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"macOS"',
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "cross-site",
        }

        # Merge with custom headers (custom headers override defaults)
        headers = {**default_headers, **(payload.headers or {})}

        emit_run_event(
            run_id,
            "prepare_request",
            "info",
            f"Prepared {payload.method} request",
            {
                "url": full_url,
                "method": payload.method,
            },
        )

        # Debug logging (minimal)
        logger.info(f"Making request to: {full_url}")

        emit_run_event(
            run_id,
            "execute_upstream",
            "info",
            f"Sending {payload.method} to upstream...",
        )

        async with httpx.AsyncClient() as client:
            logger.info(f"Making HTTP request to: {full_url}")
            response = await client.request(
                method=payload.method,
                url=full_url,
                json=payload.body if payload.method.upper() != "GET" else None,
                headers=headers,
                timeout=120.0,
            )

            logger.info(f"Response Status: {response.status_code}")
            emit_run_event(
                run_id,
                "parse_response",
                "info",
                f"Response received — HTTP {response.status_code}",
                {
                    "status_code": response.status_code,
                    "content_length": len(response.text),
                },
            )

            # Handle errors
            if response.status_code >= 400:
                logger.error(
                    f"Upstream Error ({response.status_code}): {response.text}"
                )
                error_preview = (
                    response.text[:300] if len(response.text) > 300 else response.text
                )
                emit_run_event(
                    run_id,
                    "parse_response",
                    "error",
                    f"Upstream returned HTTP {response.status_code}",
                    {
                        "status_code": response.status_code,
                        "error_preview": error_preview,
                    },
                )
                finish_run(run_id, "failed", {"upstream_status": response.status_code})
                return {
                    "error": True,
                    "status": response.status_code,
                    "message": response.text,
                    "data": None,
                    "run_id": run_id,
                }

            # Try to parse JSON response first
            try:
                json_data = response.json()
                emit_run_event(
                    run_id, "finalize", "success", "JSON response parsed successfully"
                )
                finish_run(
                    run_id, "completed", {"upstream_status": response.status_code}
                )
                if isinstance(json_data, dict):
                    json_data["run_id"] = run_id
                return json_data
            except Exception as json_error:
                logger.error(f"Failed to parse JSON response: {json_error}")
                logger.error(f"Raw response sample: {response.text[:200]}")
                emit_run_event(
                    run_id,
                    "parse_response",
                    "warn",
                    "JSON parse failed, attempting CSV parse",
                )

                # If JSON parsing fails, check if it's CSV and try to parse
                try:
                    import csv
                    from io import StringIO

                    logger.info("Attempting to parse response as CSV")
                    csv_reader = csv.DictReader(StringIO(response.text))
                    csv_data = list(csv_reader)

                    logger.info(f"Successfully parsed CSV with {len(csv_data)} rows")
                    emit_run_event(
                        run_id,
                        "finalize",
                        "success",
                        f"CSV response parsed — {len(csv_data)} rows",
                        {"row_count": len(csv_data)},
                    )
                    finish_run(
                        run_id,
                        "completed",
                        {
                            "upstream_status": response.status_code,
                            "item_count": len(csv_data),
                        },
                    )
                    return {"data": csv_data, "run_id": run_id}

                except Exception as csv_error:
                    logger.error(f"Failed to parse CSV response: {csv_error}")
                    emit_run_event(
                        run_id,
                        "parse_response",
                        "error",
                        "Both JSON and CSV parsing failed",
                    )
                    finish_run(
                        run_id, "failed", {"upstream_status": response.status_code}
                    )
                    return {
                        "error": True,
                        "status": 500,
                        "message": f"Invalid JSON or CSV response",
                        "data": None,
                        "run_id": run_id,
                    }

    except httpx.RequestError as exc:
        logger.error(f"Request Error: {exc}")
        logger.exception("Request error details:")
        emit_run_event(
            run_id,
            "execute_upstream",
            "error",
            f"Connection failed: {str(exc)}",
            {"error_type": type(exc).__name__},
        )
        finish_run(run_id, "failed")
        raise HTTPException(
            status_code=500, detail=f"Proxy connection failed: {str(exc)}"
        )
    except Exception as e:
        logger.error(f"Unexpected Error: {e}")
        logger.exception("Full exception details:")
        emit_run_event(
            run_id,
            "execute_upstream",
            "error",
            f"Unexpected error: {str(e)}",
            {"error_type": type(e).__name__},
        )
        finish_run(run_id, "failed")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        logger.info(f"=== DISCOVERY REQUEST END ===")
