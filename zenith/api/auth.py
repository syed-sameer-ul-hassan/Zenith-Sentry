#!/usr/bin/env python3
"""
Authentication and authorization for the API.
Provides JWT token support and API key validation.
"""
from fastapi import HTTPException, Security, status, Depends
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional
import jwt
import logging
import hmac
import secrets
import hashlib
from datetime import datetime, timedelta
import os

logger = logging.getLogger(__name__)

def get_jwt_secret_key():
    secret = os.getenv("ZENITH_JWT_SECRET")
    if not secret:
        raise ValueError("ZENITH_JWT_SECRET environment variable must be set")
    return secret

JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

HTTP_BEARER = HTTPBearer(auto_error=False)

def _get_valid_api_keys() -> set:
    """Load valid API keys from environment or secure key file."""
    keys = set()
    env_key = os.getenv("ZENITH_API_KEY")
    if env_key:
        keys.add(env_key.strip())
    key_file = os.getenv("ZENITH_API_KEY_FILE", "/etc/zenith-sentry/api.key")
    if os.path.exists(key_file):
        try:
            with open(key_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        keys.add(line)
        except Exception as e:
            logger.warning(f"Failed to read API key file: {e}")
    return keys

def create_jwt_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT token.
    
    Args:
        data: Data to encode in the token
        expires_delta: Optional expiration time delta
        
    Returns:
        Encoded JWT token
    """
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
    
    to_encode = data.copy()
    to_encode.update({"exp": expire})
    
    encoded_jwt = jwt.encode(to_encode, get_jwt_secret_key(), algorithm=JWT_ALGORITHM)
    return encoded_jwt

def decode_jwt_token(token: str) -> dict:
    """
    Decode and verify a JWT token.
    
    Args:
        token: JWT token to decode
        
    Returns:
        Decoded token data
        
    Raises:
        HTTPException if token is invalid
    """
    try:
        payload = jwt.decode(token, get_jwt_secret_key(), algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )

def verify_api_key(api_key: str) -> bool:
    """
    Verify an API key against configured valid keys.
    Uses constant-time comparison to prevent timing attacks.
    
    Args:
        api_key: API key to verify
        
    Returns:
        True if valid, False otherwise
    """
    if not api_key or len(api_key) < 32:
        return False
    
    valid_keys = _get_valid_api_keys()
    if not valid_keys:
        logger.error("No API keys configured. Set ZENITH_API_KEY or create key file.")
        return False
    
    for valid_key in valid_keys:
        if hmac.compare_digest(api_key, valid_key):
            return True
    return False

async def get_current_user_jwt(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTP_BEARER)
) -> Optional[dict]:
    """
    Get the current user from JWT token.
    Returns None instead of raising so fallback auth can work.
    
    Args:
        credentials: HTTP Bearer credentials
        
    Returns:
        User data from token, or None if not provided/invalid
    """
    if credentials is None:
        return None
    
    try:
        token = credentials.credentials
        payload = decode_jwt_token(token)
        return payload
    except HTTPException:
        return None
    except Exception:
        return None

async def get_current_user_api_key(
    api_key: Optional[str] = Depends(API_KEY_HEADER)
) -> Optional[str]:
    """
    Get the current user from API key.
    Returns None instead of raising so fallback auth can work.
    
    Args:
        api_key: API key from header
        
    Returns:
        API key if valid, or None if not provided/invalid
    """
    if api_key is None:
        return None
    
    if not verify_api_key(api_key):
        return None
    
    return api_key

async def get_current_user(
    jwt_user: Optional[dict] = Depends(get_current_user_jwt),
    api_key_user: Optional[str] = Depends(get_current_user_api_key)
) -> dict:
    """
    Get the current user using either JWT or API key.
    
    Args:
        jwt_user: User from JWT token
        api_key_user: User from API key
        
    Returns:
        User data
        
    Raises:
        HTTPException if neither authentication method is valid
    """
    if jwt_user is not None:
        return jwt_user
    
    if api_key_user is not None:
        return {"api_key": api_key_user, "auth_method": "api_key"}
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
        headers={"WWW-Authenticate": "Bearer"},
    )

ROLES = {
    "admin": ["read", "write", "delete", "admin"],
    "analyst": ["read", "write"],
    "viewer": ["read"]
}

def check_permission(required_permission: str, user_role: str) -> bool:
    """
    Check if a user role has the required permission.
    
    Args:
        required_permission: Permission required
        user_role: User's role
        
    Returns:
        True if user has permission, False otherwise
    """
    if user_role not in ROLES:
        return False
    
    return required_permission in ROLES[user_role]

def require_permission(permission: str):
    """
    Dependency factory to require a specific permission.
    
    Args:
        permission: Required permission
        
    Returns:
        Dependency function
    """
    async def permission_checker(current_user: dict = Depends(get_current_user)):
        user_role = current_user.get("role", "viewer")
        
        if not check_permission(permission, user_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permission}' required"
            )
        
        return current_user
    
    return permission_checker
