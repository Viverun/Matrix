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

from config import get_settings
from core.database import init_db, close_db
from api import auth_router, scans_router, vulnerabilities_router, test_bench
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
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        
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

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.debug else ["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add security headers middleware
app.add_middleware(SecurityHeadersMiddleware)


# Health check endpoint
@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
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
