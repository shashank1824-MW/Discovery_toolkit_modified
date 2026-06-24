"""
Google SSO Authentication Router
Handles OAuth2 flow, JWT session management, and email allowlist via AWS SSM.
"""

import os
import json
import secrets
import logging
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
import jwt
from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

logger = logging.getLogger("uvicorn")

router = APIRouter(prefix="/auth", tags=["authentication"])

# ============================================================
# Configuration
# ============================================================

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev-secret-change-me-in-production")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")
BACKEND_URL = os.getenv("BACKEND_URL", "").rstrip("/")
ALLOWED_DOMAIN = os.getenv("ALLOWED_DOMAIN", "meltwater.com")

# JWT settings
JWT_ALGORITHM = "HS256"
# Set to 8 hours for production (standard workday)
JWT_EXPIRATION_MINUTES = 480

# Google OAuth2 endpoints
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"

import sqlite3

# SQLite database path
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "auth.db")

# Run DB init on startup
def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS allowlist (
                email TEXT PRIMARY KEY,
                is_admin BOOLEAN NOT NULL DEFAULT 0,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()

init_db()

# ============================================================
# SQLite Allowlist Helpers
# ============================================================

def get_allowlist() -> list[dict]:
    """Fetch all permitted users from SQLite."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT email, is_admin FROM allowlist")
        rows = cursor.fetchall()
        return [{"email": dict(row)["email"], "is_admin": bool(dict(row)["is_admin"])} for row in rows]

def is_email_allowed(email: str) -> tuple[bool, str, bool]:
    """
    Two-layer validation:
    1. Check domain is @meltwater.com
    2. Check email is in SQLite allowlist
    
    If DB is completely empty, the very first @meltwater.com user 
    is automatically added as an admin!
    
    Returns (is_allowed, error_message, is_admin)
    """
    email_lower = email.lower().strip()
    domain = email_lower.split("@")[-1] if "@" in email_lower else ""

    if domain != ALLOWED_DOMAIN:
        return False, "domain_not_allowed", False

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        
        # Check if DB is totally empty
        cursor.execute("SELECT COUNT(*) FROM allowlist")
        count = cursor.fetchone()[0]
        
        if count == 0:
            logger.info(f"[Auth] Database is empty. Bootstrapping {email_lower} as the first Admin!")
            cursor.execute("INSERT INTO allowlist (email, is_admin) VALUES (?, 1)", (email_lower,))
            conn.commit()
            return True, "", True

        # Check if user exists
        cursor.execute("SELECT is_admin FROM allowlist WHERE email = ?", (email_lower,))
        row = cursor.fetchone()
        
        if not row:
            return False, "email_not_authorized", False
            
        is_admin = bool(row[0])
        return True, "", is_admin

# ============================================================
# JWT Helpers
# ============================================================

def create_jwt_token(user_info: dict) -> str:
    """Create a JWT token with user info and expiration."""
    payload = {
        "email": user_info["email"],
        "name": user_info.get("name", ""),
        "picture": user_info.get("picture", ""),
        "is_admin": user_info.get("is_admin", False),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRATION_MINUTES),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_jwt_token(token: str) -> dict:
    """Decode and validate a JWT token. Raises on invalid/expired tokens."""
    return jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])


# ============================================================
# Auth Dependency (for protecting endpoints)
# ============================================================

def get_current_user(request: Request) -> dict:
    """
    FastAPI dependency to extract and validate the user from the JWT.
    Checks X-Auth-Token header (to avoid collision with Meltwater's Authorization header).
    """
    token = request.headers.get("X-Auth-Token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        payload = decode_jwt_token(token)
        return {
            "email": payload["email"],
            "name": payload.get("name", ""),
            "picture": payload.get("picture", ""),
            "is_admin": payload.get("is_admin", False),
        }
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ============================================================
# Routes
# ============================================================

@router.get("/google/login")
async def google_login(request: Request):
    """Redirect user to Google's OAuth2 consent screen."""
    if not GOOGLE_CLIENT_ID:
        raise HTTPException(status_code=500, detail="GOOGLE_CLIENT_ID not configured")

    # Build the callback URL
    if BACKEND_URL:
        # Use explicit backend URL if provided (preferred for prod)
        callback_url = f"{BACKEND_URL}/auth/google/callback"
    else:
        # Fallback to dynamic (good for local dev)
        callback_url = str(request.base_url).rstrip("/") + "/auth/google/callback"
        
    # Force HTTPS in production if it's currently HTTP
    if "localhost" not in callback_url and "127.0.0.1" not in callback_url:
        callback_url = callback_url.replace("http://", "https://")

    # anti-CSRF state parameter
    state = secrets.token_urlsafe(32)

    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": callback_url,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "state": state,
        # Restrict to meltwater.com domain at Google's level too
        "hd": ALLOWED_DOMAIN,
    }

    auth_url = f"{GOOGLE_AUTH_URL}?{urllib.parse.urlencode(params)}"
    return RedirectResponse(url=auth_url)


@router.get("/google/callback")
async def google_callback(code: str = "", error: str = "", state: str = "", request: Request = None):
    """
    Handle Google OAuth2 callback.
    Exchanges auth code for tokens, validates domain + allowlist, creates JWT.
    """
    # Build the same callback URL for token exchange
    if BACKEND_URL:
        callback_url = f"{BACKEND_URL}/auth/google/callback"
    else:
        callback_url = str(request.base_url).rstrip("/") + "/auth/google/callback"
        
    if "localhost" not in callback_url and "127.0.0.1" not in callback_url:
        callback_url = callback_url.replace("http://", "https://")
        
    if error:
        return RedirectResponse(
            url=f"{FRONTEND_URL}/auth/callback/?error={urllib.parse.quote(error)}"
        )

    if not code:
        return RedirectResponse(
            url=f"{FRONTEND_URL}/auth/callback/?error=no_code"
        )

    # Build the callback URL to match what was sent to Google

    try:
        # Exchange auth code for tokens
        async with httpx.AsyncClient() as client:
            token_response = await client.post(
                GOOGLE_TOKEN_URL,
                data={
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": callback_url,
                },
            )

            if token_response.status_code != 200:
                logger.error(f"[Auth] Token exchange failed: {token_response.text}")
                return RedirectResponse(
                    url=f"{FRONTEND_URL}/auth/callback/?error=token_exchange_failed"
                )

            tokens = token_response.json()
            access_token = tokens.get("access_token")

            # Fetch user info from Google
            userinfo_response = await client.get(
                GOOGLE_USERINFO_URL,
                headers={"Authorization": f"Bearer {access_token}"},
            )

            if userinfo_response.status_code != 200:
                logger.error(f"[Auth] Userinfo fetch failed: {userinfo_response.text}")
                return RedirectResponse(
                    url=f"{FRONTEND_URL}/auth/callback/?error=userinfo_failed"
                )

            user_info = userinfo_response.json()
            email = user_info.get("email", "")

            logger.info(f"[Auth] Google login attempt: {email}")

            # Two-layer validation
            allowed, error_code, is_admin = is_email_allowed(email)
            if not allowed:
                logger.warning(f"[Auth] Access denied for {email}: {error_code}")
                return RedirectResponse(
                    url=f"{FRONTEND_URL}/auth/callback/?error={error_code}"
                )

            # Create JWT
            user_info["is_admin"] = is_admin
            jwt_token = create_jwt_token(user_info)
            logger.info(f"[Auth] Login successful: {email} (Admin: {is_admin})")

            return RedirectResponse(
                url=f"{FRONTEND_URL}/auth/callback/?token={jwt_token}"
            )

    except Exception as e:
        logger.error(f"[Auth] Callback error: {e}")
        return RedirectResponse(
            url=f"{FRONTEND_URL}/auth/callback/?error=server_error"
        )


@router.get("/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    """Return current authenticated user info."""
    return current_user


# ============================================================
# Allowlist Management Endpoints (Admin Only)
# ============================================================

def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    """Dependency that ensures the current user is an admin."""
    if not current_user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

class AllowlistAddRequest(BaseModel):
    email: str
    is_admin: bool = False

@router.get("/allowlist")
async def get_allowlist_endpoint(admin_user: dict = Depends(require_admin)):
    """Get the current email allowlist."""
    return {"emails": get_allowlist()}

@router.post("/allowlist")
async def add_to_allowlist(
    body: AllowlistAddRequest,
    admin_user: dict = Depends(require_admin),
):
    """Add an email to the allowlist."""
    email = body.email.lower().strip()

    # Validate domain
    if not email.endswith(f"@{ALLOWED_DOMAIN}"):
        raise HTTPException(
            status_code=400,
            detail=f"Email must be a @{ALLOWED_DOMAIN} address",
        )

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO allowlist (email, is_admin) VALUES (?, ?)", 
                (email, int(body.is_admin))
            )
            conn.commit()
            logger.info(f"[Auth] Admin {admin_user['email']} added {email} (is_admin={body.is_admin})")
            return {"emails": get_allowlist(), "message": f"Added {email}"}
        except sqlite3.IntegrityError:
            # If email already exists, update the admin status instead
            cursor.execute(
                "UPDATE allowlist SET is_admin = ? WHERE email = ?",
                (int(body.is_admin), email)
            )
            conn.commit()
            logger.info(f"[Auth] Admin {admin_user['email']} updated {email} (is_admin={body.is_admin})")
            return {"emails": get_allowlist(), "message": f"Updated {email}"}

@router.delete("/allowlist/{email}")
async def remove_from_allowlist(
    email: str,
    admin_user: dict = Depends(require_admin),
):
    """Remove an email from the allowlist."""
    email = email.lower().strip()

    # Prevent removing yourself
    if email == admin_user["email"].lower():
        raise HTTPException(status_code=400, detail="Cannot remove yourself from the allowlist")

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM allowlist WHERE email = ?", (email,))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Email not in allowlist")
        conn.commit()

    logger.info(f"[Auth] Admin {admin_user['email']} removed {email} from allowlist")
    return {"emails": get_allowlist(), "message": f"Removed {email}"}
