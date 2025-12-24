"""API routes package."""
from .auth import router as auth_router
from .scans import router as scans_router
from .vulnerabilities import router as vulnerabilities_router

__all__ = ["auth_router", "scans_router", "vulnerabilities_router"]
