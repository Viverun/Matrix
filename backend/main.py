"""
Matrix - Agent-Driven Cyber Threat Simulator
Main FastAPI Application
"""
import secrets
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from config import get_settings
from core.database import init_db, close_db
from api import auth_router, scans_router, vulnerabilities_router, chatbot_router, test_bench
from agents.orchestrator import orchestrator
from agents.xss_agent import XSSAgent
from agents.sql_injection_agent import SQLInjectionAgent
from agents.auth_agent import AuthenticationAgent
from agents.api_security_agent import APISecurityAgent

settings = get_settings()


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add security headers to all responses.
    
    Applied headers:
    - X-Content-Type-Options: nosniff (prevent MIME sniffing)
    - X-Frame-Options: DENY (prevent clickjacking)
    - Referrer-Policy: no-referrer-when-downgrade
    - Content-Security-Policy: Restrictive policy for API service
    - Strict-Transport-Security: HTTPS only, with preload (requires all subdomains to support HTTPS)
    - Permissions-Policy: Restrict browser features
    """
    
    # Whether to use strict API-only CSP (default-src 'none') or allow 'self'
    API_ONLY_MODE = True
    
    # HSTS preload requires ALL subdomains to support HTTPS
    # Set to False if any subdomain doesn't support HTTPS
    HSTS_PRELOAD_ENABLED = True
    
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # In Debug/Dev mode, skip strict security headers to avoid CORS/Fetch issues on localhost
        if settings.debug:
            return response

        # Generate unique CSP nonce per response (NEVER reuse)
        nonce = secrets.token_urlsafe(16)
        
        # Prevent MIME sniffing attacks
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # Prevent clickjacking/UI redressing
        response.headers["X-Frame-Options"] = "DENY"
        
        # Control referrer information leakage
        response.headers["Referrer-Policy"] = "no-referrer-when-downgrade"
        
        # Content Security Policy - restrictive for API-only service
        if self.API_ONLY_MODE:
            # API-only: deny all content loading (JSON responses don't need scripts/styles)
            response.headers["Content-Security-Policy"] = (
                "default-src 'none'; "
                "frame-ancestors 'none'; "
                "base-uri 'none'; "
                "form-action 'none'; "
                "upgrade-insecure-requests"
            )
        else:
            # Web app mode: allow self with nonce-based scripts
            response.headers["Content-Security-Policy"] = (
                "default-src 'none'; "
                f"script-src 'self' 'nonce-{nonce}'; "
                "style-src 'self'; "
                "img-src 'self' data:; "
                "font-src 'self'; "
                "connect-src 'self'; "
                "object-src 'none'; "
                "frame-ancestors 'none'; "
                "base-uri 'self'; "
                "form-action 'self'; "
                "upgrade-insecure-requests"
            )
        
        # Store nonce in request state for templates (if needed)
        # Templates can access via request.state.csp_nonce
        
        # HSTS - ONLY on HTTPS connections
        # WARNING: preload directive requires ALL subdomains to enforce HTTPS
        forwarded_proto = request.headers.get("x-forwarded-proto", "")
        is_https = request.url.scheme == "https" or forwarded_proto == "https"
        
        if is_https:
            hsts_value = "max-age=31536000; includeSubDomains"
            if self.HSTS_PRELOAD_ENABLED:
                # Only add preload if you're certain all subdomains support HTTPS
                hsts_value += "; preload"
            response.headers["Strict-Transport-Security"] = hsts_value
        
        # Permissions Policy - restrict powerful browser features
        response.headers["Permissions-Policy"] = (
            "geolocation=(), "
            "microphone=(), "
            "camera=(), "
            "payment=(), "
            "usb=(), "
            "magnetometer=(), "
            "gyroscope=(), "
            "accelerometer=()"
        )
        
        # Cross-Origin policies for additional isolation
        # 'cross-origin' allows CORS-enabled requests from other origins
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "cross-origin"
        
        return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    # Startup
    print("Starting Matrix...")
    await init_db()
    
    # Register agents
    orchestrator.register_agent(XSSAgent())
    orchestrator.register_agent(SQLInjectionAgent())
    orchestrator.register_agent(AuthenticationAgent())
    orchestrator.register_agent(APISecurityAgent())
    print("[Main] Security agents registered")
    
    print("Database initialized and Agents registered")
    
    yield
    
    # Shutdown
    print("🔄 Shutting down Matrix...")
    await close_db()
    print("✅ Cleanup complete")


# Create FastAPI application
app = FastAPI(
    title="Matrix",
    description="Agent-Driven Cyber Threat Simulator - AI-powered security testing platform",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)



from core.api_limiter import limiter

from core.csrf import CSRFMiddleware

# Initialize Rate Limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(CSRFMiddleware) # Added inner to SlowAPI (runs after SlowAPI)
app.add_middleware(SlowAPIMiddleware)

# Add security headers middleware FIRST (inner layer)
app.add_middleware(SecurityHeadersMiddleware)

from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts="*")

# Configure CORS with dynamic origin validation for Vercel preview deployments
# Vercel creates new preview URLs for each deployment, so we need pattern matching
origins = [origin.strip() for origin in settings.allowed_origins.split(",") if origin.strip()]

def is_allowed_origin(origin: str) -> bool:
    """Check if origin is allowed (supports Vercel preview deployments)."""
    if not origin:
        return False
    
    # Allow exact matches from ALLOWED_ORIGINS
    if origin in origins:
        return True
    
    # Allow all Vercel preview deployments (*.vercel.app)
    if origin.endswith('.vercel.app') and origin.startswith('https://'):
        return True
    
    # Allow localhost for development
    if 'localhost' in origin or '127.0.0.1' in origin:
        return True
    
    return False

# Custom CORS middleware to handle dynamic origins
from starlette.middleware.cors import CORSMiddleware as StarletteCORS
from starlette.types import ASGIApp, Receive, Scope, Send

class DynamicCORSMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app
    
    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        
        # Get origin from headers
        headers = dict(scope.get("headers", []))
        origin = headers.get(b"origin", b"").decode("utf-8")
        method = scope.get("method", "")
        
        # Check if origin is allowed
        if is_allowed_origin(origin):
            # Handle OPTIONS preflight requests
            if method == "OPTIONS":
                async def send_options_response(message):
                    if message["type"] == "http.response.start":
                        message["status"] = 200
                        message["headers"] = [
                            (b"access-control-allow-origin", origin.encode()),
                            (b"access-control-allow-credentials", b"true"),
                            (b"access-control-allow-methods", b"GET, POST, PUT, DELETE, OPTIONS, PATCH"),
                            (b"access-control-allow-headers", b"content-type, authorization, x-csrf-token, x-requested-with, accept, origin"),
                            (b"access-control-max-age", b"86400"),
                            (b"content-length", b"0"),
                        ]
                    await send(message)
                
                await send_options_response({"type": "http.response.start"})
                await send({"type": "http.response.body", "body": b""})
                return
            
            # Add CORS headers to regular requests
            async def send_with_cors(message):
                if message["type"] == "http.response.start":
                    headers = list(message.get("headers", []))
                    headers.append((b"access-control-allow-origin", origin.encode()))
                    headers.append((b"access-control-allow-credentials", b"true"))
                    headers.append((b"access-control-allow-methods", b"GET, POST, PUT, DELETE, OPTIONS, PATCH"))
                    headers.append((b"access-control-allow-headers", b"content-type, authorization, x-csrf-token, x-requested-with, accept, origin"))
                    message["headers"] = headers
                await send(message)
            
            await self.app(scope, receive, send_with_cors)
        else:
            await self.app(scope, receive, send)

app.add_middleware(DynamicCORSMiddleware)


# Health check endpoint
@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint to verify API and database connectivity."""
    return {"status": "ok", "message": "Matrix API is operational"}


@app.get("/api/csrf/", tags=["Security"])
async def get_csrf_init(request: Request, response: Response):
    """Endpoint to initialize CSRF cookie for the frontend."""
    from core.security import create_csrf_token, verify_csrf_token
    
    # Check if we have a valid token in request cookies
    csrf_token = request.cookies.get("CSRF-TOKEN")
    
    # If not valid, generate a new one
    if not csrf_token or not verify_csrf_token(csrf_token):
        csrf_token = create_csrf_token()
        # Also set it as a cookie for browsers that DO allow them
        response.set_cookie(
            key="CSRF-TOKEN",
            value=csrf_token,
            httponly=False,
            samesite="none",
            secure=True,
            path="/"
        )
    
    return {
        "status": "CSRF initialized",
        "csrf_token": csrf_token,  # Crucial: Return in body for JS
        "app": settings.app_name,
        "version": "1.0.0"
    }


# API info endpoint
@app.get("/", tags=["Info"])
async def root():
    """API information."""
    return {
        "name": "Matrix API",
        "description": "Agent-Driven Cyber Threat Simulator",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health"
    }


# Register routers
app.include_router(auth_router, prefix="/api")
app.include_router(scans_router, prefix="/api")
app.include_router(vulnerabilities_router, prefix="/api")
app.include_router(chatbot_router, prefix="/api")
app.include_router(test_bench.router, prefix="/api")


# Exception handlers
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler."""
    return JSONResponse(
        status_code=500,
        content={
            "detail": "An internal error occurred",
            "error": str(exc) if settings.debug else "Internal Server Error"
        }
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug
    )
