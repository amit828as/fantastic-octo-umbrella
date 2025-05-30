from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
import time
from datetime import datetime

# Import routers
from app.routers import organization, auth
from app.database.database import get_database

app = FastAPI(
    title="Organization Management API",
    description="A REST API for managing organizations and admin authentication",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    """Root endpoint to verify API is running"""
    return {
        "message": "Organization Management API",
        "status": "running",
        "version": "1.0.0"
    }

@app.get("/health")
async def health_check(db: AsyncSession = Depends(get_database)):
    """
    Comprehensive health check endpoint
    Checks API status and database connectivity
    """
    start_time = time.time()
    health_data = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
        "checks": {}
    }
    
    try:
        # Test database connectivity
        db_start = time.time()
        result = await db.execute(text("SELECT 1"))
        db_time = (time.time() - db_start) * 1000  # Convert to milliseconds
        
        health_data["checks"]["database"] = {
            "status": "healthy",
            "response_time_ms": round(db_time, 2)
        }
    except Exception as e:
        health_data["status"] = "unhealthy"
        health_data["checks"]["database"] = {
            "status": "unhealthy",
            "error": str(e)
        }
    
    # Overall response time
    total_time = (time.time() - start_time) * 1000
    health_data["response_time_ms"] = round(total_time, 2)
    
    # Return appropriate HTTP status
    if health_data["status"] == "unhealthy":
        raise HTTPException(status_code=503, detail=health_data)
    
    return health_data

# Router includes
app.include_router(organization.router, prefix="/api/v1")
app.include_router(auth.router) 