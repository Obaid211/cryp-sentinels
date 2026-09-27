import jwt
from typing import Optional, Dict, Any
from fastapi import Header, HTTPException, status, Depends
from app.core.config import settings

def get_current_user(
    authorization: Optional[str] = Header(None, alias="Authorization")
) -> Dict[str, Any]:
    """
    FastAPI dependency to extract and verify Supabase JWT.
    
    Behavior:
    1. If an 'Authorization: Bearer <token>' header is present:
       - If SUPABASE_JWT_SECRET is configured, verifies the JWT signature and expiration.
       - Otherwise, safely decodes the unverified payload with expiration checking.
       - On validation failure, raises 401 Unauthorized.
    2. If no Authorization header is present:
       - If settings.REQUIRE_AUTH is True, raises 401 Unauthorized.
       - If settings.REQUIRE_AUTH is False (demo / local dev / air-gapped mode), returns a demo guest identity.
    """
    if not authorization:
        if settings.REQUIRE_AUTH:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing Authorization header",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return {
            "sub": "guest-anonymous",
            "role": "authenticated",
            "email": "guest@ecdat.internal",
            "is_anonymous": True,
        }

    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header format. Expected 'Bearer <token>'",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = parts[1]

    try:
        if settings.SUPABASE_JWT_SECRET:
            payload = jwt.decode(
                token,
                settings.SUPABASE_JWT_SECRET,
                algorithms=["HS256", "RS256"],
                audience="authenticated",
                options={"verify_exp": True},
            )
        else:
            # Decode payload without secret verification when SUPABASE_JWT_SECRET is not yet set
            payload = jwt.decode(
                token,
                options={"verify_signature": False, "verify_exp": True},
            )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid authentication token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )
