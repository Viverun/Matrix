"""
Security utilities for authentication and authorization.
"""
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt
from jose.exceptions import ExpiredSignatureError
from passlib.context import CryptContext

from config import get_settings
from core.logger import get_logger

logger = get_logger(__name__)
settings = get_settings()

# Password hashing context - using argon2 for better security
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


class SecurityError(Exception):
    """Base exception for security-related errors."""
    pass


class TokenError(SecurityError):
    """Exception raised for token-related errors."""
    pass


class PasswordError(SecurityError):
    """Exception raised for password-related errors."""
    pass


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against its hash.
    
    Args:
        plain_password: Plain text password to verify
        hashed_password: Hashed password to check against
    
    Returns:
        True if password matches, False otherwise
    """
    try:
        result = pwd_context.verify(plain_password, hashed_password)
        if result:
            logger.debug("Password verification successful")
        else:
            logger.debug("Password verification failed - incorrect password")
        return result
    except ValueError as e:
        logger.error(f"Invalid hash format: {e}")
        return False
    except Exception as e:
        logger.error(f"Password verification error: {e}", exc_info=True)
        return False


def get_password_hash(password: str) -> str:
    """
    Generate password hash using argon2.
    
    Args:
        password: Plain text password to hash
    
    Returns:
        Hashed password string
    
    Raises:
        PasswordError: If password hashing fails
    """
    if not password or len(password.strip()) == 0:
        raise PasswordError("Password cannot be empty")
    
    try:
        hashed = pwd_context.hash(password)
        logger.debug("Password hashed successfully")
        return hashed
    except Exception as e:
        logger.error(f"Password hashing failed: {e}", exc_info=True)
        raise PasswordError(f"Failed to hash password: {str(e)}")


def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create a JWT access token.
    
    Args:
        data: Dictionary containing claims to encode in the token
        expires_delta: Optional custom expiration time
    
    Returns:
        Encoded JWT token string
    
    Raises:
        TokenError: If token creation fails
    """
    try:
        to_encode = data.copy()
        
        # Use timezone-aware datetime
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(
                minutes=settings.access_token_expire_minutes
            )
        
        to_encode.update({"exp": expire})
        
        encoded_jwt = jwt.encode(
            to_encode,
            settings.secret_key,
            algorithm=settings.algorithm
        )
        
        logger.info(
            f"Access token created for subject: {data.get('sub', 'unknown')}",
            extra={"subject": data.get('sub'), "expires_in_minutes": settings.access_token_expire_minutes}
        )
        
        return encoded_jwt
    
    except Exception as e:
        logger.error(f"Token creation failed: {e}", exc_info=True)
        raise TokenError(f"Failed to create access token: {str(e)}")


def decode_token(token: str) -> Optional[dict]:
    """
    Decode and verify a JWT token.
    
    Args:
        token: JWT token string to decode
    
    Returns:
        Dictionary containing token payload if valid, None otherwise
    """
    if not token or len(token.strip()) == 0:
        logger.warning("Token decode attempted with empty token")
        return None
    
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.algorithm]
        )
        
        logger.debug(
            f"Token decoded successfully for subject: {payload.get('sub', 'unknown')}",
            extra={"subject": payload.get('sub')}
        )
        
        return payload
    
    except ExpiredSignatureError:
        logger.warning(
            "Token decode failed - token expired",
            extra={"token_preview": token[:20] + "..."}
        )
        return None
    
    except JWTError as e:
        logger.error(
            f"JWT decode error: {e}",
            extra={
                "error_type": type(e).__name__,
                "token_preview": token[:20] + "...",
                "secret_preview": settings.secret_key[:10] + "..."
            }
        )
        return None
    
    except Exception as e:
        logger.error(f"Unexpected error decoding token: {e}", exc_info=True)
        return None


def validate_token(token: str) -> bool:
    """
    Validate a JWT token without returning the payload.
    
    Args:
        token: JWT token string to validate
    
    Returns:
        True if token is valid, False otherwise
    """
    return decode_token(token) is not None


def extract_user_id(token: str) -> Optional[str]:
    """
    Extract user ID from a JWT token.
    
    Args:
        token: JWT token string
    
    Returns:
        User ID if token is valid and contains 'sub' claim, None otherwise
    """
    payload = decode_token(token)
    if payload:
        return payload.get("sub")
    return None


def create_refresh_token(data: dict, expires_days: int = 7) -> str:
    """
    Create a JWT refresh token with longer expiration.
    
    Args:
        data: Dictionary containing claims to encode
        expires_days: Number of days until token expires
    
    Returns:
        Encoded JWT refresh token string
    
    Raises:
        TokenError: If token creation fails
    """
    expires_delta = timedelta(days=expires_days)
    return create_access_token(data, expires_delta)


def verify_token_signature(token: str) -> bool:
    """
    Verify token signature without checking expiration.
    
    Args:
        token: JWT token string
    
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.algorithm],
            options={"verify_exp": False}  # Skip expiration check
        )
        return True
    except JWTError:
        return False
    except Exception as e:
        logger.error(f"Signature verification error: {e}")
        return False