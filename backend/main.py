"""
Matrix - Agent-Driven Cyber Threat Simulator
Main FastAPI Application
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config import get_settings
from core.database import init_db, close_db
from api import auth_router, scans_router, vulnerabilities_router, test_bench
from agents.orchestrator import orchestrator
from agents.xss_agent import XSSAgent
from agents.sql_injection_agent import SQLInjectionAgent
from agents.auth_agent import AuthenticationAgent
from agents.api_security_agent import APISecurityAgent

settings = get_settings()


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
