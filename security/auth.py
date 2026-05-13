"""
security/auth.py
 
Authentication module.
Handles password hashing with bcrypt and JWT token operations.
"""

import os

import bcrypt
import jwt
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

# Load .env so SECRET_KEY is available before any function is called
load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"

# Fail fast — never start with a missing secret key
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable is not set.")

def hash_password(password):
    """Hash a plain-text password with bcrypt.
 
    gensalt() adds a random salt so identical passwords produce
    different hashes — prevents rainbow-table attacks.
    Always called at registration, never at login.
 
    Args:
        password: Plain-text password supplied by the user.
 
    Returns:
        Bcrypt hash as bytes, safe to store in the database.
    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

def verify_password(plain, hashed):
    """Compare a plain-text password against a stored bcrypt hash.
 
    checkpw() does not decrypt the hash — it re-hashes the plain
    password with the same salt and compares the results.
 
    Args:
        plain:  Password the user typed at login.
        hashed: Hash retrieved from the database.
 
    Returns:
        True if the password matches, False otherwise.
    """
    return bcrypt.checkpw(plain.encode("utf-8"), hashed)

def create_access_token(user_id, role):
    """Create a signed JWT access token.
 
    The token carries the user identity and role so downstream
    handlers can authorise requests without a database lookup.
 
    Args:
        user_id: Unique identifier of the authenticated user.
        role:    Permission level (e.g. "doctor", "nurse").
 
    Returns:
        Signed JWT string valid for 24 hours.
    """
    payload = {
        "user_id": user_id,
        "role"   : role,
        # exp → expiry time; jwt.decode() rejects tokens past this point
        "exp"    : datetime.now(timezone.utc) + timedelta(hours=24),
        # iat → issued-at timestamp; useful for audit trails
        "iat"    : datetime.now(timezone.utc),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def verify_access_token(token):
    """Verify and decode a JWT access token.
 
    Args:
        token: JWT string from the request Authorization header.
 
    Returns:
        Decoded payload dict on success, None on any failure.
    """
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        return None # token is past its expiry time
    except jwt.InvalidTokenError:
        return None # tampered, malformed, or wrong key