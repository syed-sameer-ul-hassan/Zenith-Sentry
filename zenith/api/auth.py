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
    Verify an API key.
    
    In production, this would check against the database.
    For now, this is a simple placeholder.
    
    Args:
        api_key: API key to verify
        
    Returns:
        True if valid, False otherwise
    """
                                           
    if not api_key or len(api_key) < 32:
        return False
    return True

async def get_current_user_jwt(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTP_BEARER)
) -> dict:
    """
    Get the current user from JWT token.
    
    Args:
        credentials: HTTP Bearer credentials
        
    Returns:
        User data from token
        
    Raises:
        HTTPException if credentials are invalid
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = credentials.credentials
    payload = decode_jwt_token(token)
    
    return payload

async def get_current_user_api_key(
    api_key: Optional[str] = Depends(API_KEY_HEADER)
) -> str:
    """
    Get the current user from API key.
    
    Args:
        api_key: API key from header
        
    Returns:
        API key
        
    Raises:
        HTTPException if API key is invalid
    """
    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required",
            headers={"X-API-Key": "Required"},
        )
    
    if not verify_api_key(api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )
    
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
        detail="Authentication required"
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
