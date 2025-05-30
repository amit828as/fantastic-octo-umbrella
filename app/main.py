from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Import routers (will be added in future tasks)
# from app.routers import organization, admin

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
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}

# Router includes (will be added in future tasks)
# app.include_router(organization.router, prefix="/api/v1")
# app.include_router(admin.router, prefix="/api/v1") 