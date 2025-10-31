#!/usr/bin/env python3
"""SMCP Security Framework - Hosted API Service

A hosted Security-as-a-Service API for SMCP security validation.
Deploys to Render.com for easy cloud access.
"""

import os
import sys
import asyncio
import logging
from datetime import datetime
from typing import Dict, Any, Optional

from fastapi import FastAPI, HTTPException, Depends, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import uvicorn

# Add SMCPv1 code to path
sys.path.insert(0, '/app/SMCPv1/code')

from smcp_security import (
    SMCPSecurityFramework,
    SecurityConfig,
    SecurityError,
    ValidationError,
    AuthenticationError,
    AuthorizationError,
    RateLimitError
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Security bearer token
security = HTTPBearer(auto_error=False)

# Global security framework instance
security_framework: Optional[SMCPSecurityFramework] = None

# Request/Response models
class SecurityValidationRequest(BaseModel):
    """Request model for security validation"""
    request: Dict[str, Any] = Field(..., description="MCP request to validate")
    context: Dict[str, Any] = Field(..., description="User context information")
    config: Optional[Dict[str, Any]] = Field(None, description="Optional security configuration override")

class SecurityValidationResponse(BaseModel):
    """Response model for security validation"""
    success: bool = Field(..., description="Whether validation succeeded")
    request: Optional[Dict[str, Any]] = Field(None, description="Validated and sanitized request")
    context: Optional[Dict[str, Any]] = Field(None, description="Enhanced context information")
    security_metadata: Optional[Dict[str, Any]] = Field(None, description="Security processing metadata")
    error: Optional[str] = Field(None, description="Error message if validation failed")
    error_code: Optional[str] = Field(None, description="Error code for programmatic handling")

class HealthResponse(BaseModel):
    """Health check response"""
    status: str = Field(..., description="Service status")
    version: str = Field(..., description="API version")
    timestamp: str = Field(..., description="Current timestamp")
    uptime_seconds: float = Field(..., description="Service uptime in seconds")

class MetricsResponse(BaseModel):
    """Metrics response"""
    requests_processed: int = Field(..., description="Total requests processed")
    requests_blocked: int = Field(..., description="Total requests blocked")
    average_processing_time_ms: float = Field(..., description="Average processing time")
    security_score: float = Field(..., description="Overall security score")
    uptime_seconds: float = Field(..., description="Service uptime")

# Global metrics
metrics = {
    "requests_processed": 0,
    "requests_blocked": 0,
    "processing_times": [],
    "start_time": datetime.utcnow()
}

# Simple API key validation (in production, use proper auth service)
VALID_API_KEYS = {
    "demo_key_123": {"name": "Demo User", "tier": "free", "rate_limit": 1000},
    "test_key_456": {"name": "Test User", "tier": "basic", "rate_limit": 5000},
    os.environ.get("SMCP_MASTER_KEY", "master_key_789"): {"name": "Master", "tier": "unlimited", "rate_limit": -1}
}

def verify_api_key(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    """Verify API key from Authorization header"""
    if not credentials:
        # Allow unauthenticated access for demo (with rate limits)
        return {"name": "Anonymous", "tier": "demo", "rate_limit": 100}
    
    api_key = credentials.credentials
    if api_key not in VALID_API_KEYS:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    return VALID_API_KEYS[api_key]

def initialize_security_framework() -> SMCPSecurityFramework:
    """Initialize the security framework with configuration from environment"""
    config = SecurityConfig(
        enable_input_validation=True,
        validation_strictness=os.environ.get("SMCP_VALIDATION_STRICTNESS", "standard"),
        enable_mfa=os.environ.get("SMCP_ENABLE_MFA", "false").lower() == "true",
        enable_rbac=True,
        enable_rate_limiting=True,
        default_rate_limit=int(os.environ.get("SMCP_RATE_LIMIT", "100")),
        enable_encryption=True,
        enable_ai_immune=True,
        anomaly_threshold=float(os.environ.get("SMCP_ANOMALY_THRESHOLD", "0.7")),
        enable_audit_logging=True,
        log_level=os.environ.get("SMCP_LOG_LEVEL", "INFO")
    )
    
    return SMCPSecurityFramework(config)

# Create FastAPI app
app = FastAPI(
    title="SMCP Security API",
    description="Hosted Security-as-a-Service for Model Context Protocol implementations",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify allowed origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    """Initialize services on startup"""
    global security_framework
    
    logger.info("Starting SMCP Security API service...")
    
    try:
        security_framework = initialize_security_framework()
        logger.info("Security framework initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize security framework: {e}")
        raise
    
    logger.info("SMCP Security API service started successfully")

@app.get("/", response_model=Dict[str, str])
async def root():
    """Root endpoint with service information"""
    return {
        "service": "SMCP Security API",
        "version": "1.0.0",
        "description": "Hosted Security-as-a-Service for Model Context Protocol",
        "docs": "/docs",
        "health": "/health",
        "github": "https://github.com/wizardscurtain/SMCPv1"
    }

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    uptime = (datetime.utcnow() - metrics["start_time"]).total_seconds()
    
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        timestamp=datetime.utcnow().isoformat(),
        uptime_seconds=uptime
    )

@app.get("/metrics", response_model=MetricsResponse)
async def get_metrics(user: Dict[str, Any] = Depends(verify_api_key)):
    """Get service metrics"""
    uptime = (datetime.utcnow() - metrics["start_time"]).total_seconds()
    avg_processing_time = (
        sum(metrics["processing_times"]) / len(metrics["processing_times"])
        if metrics["processing_times"] else 0.0
    )
    
    # Calculate security score based on configuration and metrics
    security_score = 85.0  # Base score
    if security_framework:
        if security_framework.config.enable_mfa:
            security_score += 5
        if security_framework.config.validation_strictness == "maximum":
            security_score += 5
        elif security_framework.config.validation_strictness == "standard":
            security_score += 3
    
    return MetricsResponse(
        requests_processed=metrics["requests_processed"],
        requests_blocked=metrics["requests_blocked"],
        average_processing_time_ms=avg_processing_time,
        security_score=security_score,
        uptime_seconds=uptime
    )

@app.post("/validate", response_model=SecurityValidationResponse)
async def validate_request(
    validation_request: SecurityValidationRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    user: Dict[str, Any] = Depends(verify_api_key)
):
    """Validate MCP request through security framework"""
    start_time = datetime.utcnow()
    
    try:
        # Add client IP to context
        client_ip = request.client.host
        enhanced_context = {
            **validation_request.context,
            "client_ip": client_ip,
            "user_agent": request.headers.get("user-agent", "unknown"),
            "api_user": user["name"],
            "api_tier": user["tier"]
        }
        
        # Override security config if provided
        if validation_request.config:
            # Create temporary security framework with custom config
            custom_config = SecurityConfig(**validation_request.config)
            temp_security = SMCPSecurityFramework(custom_config)
            result = await temp_security.process_request(
                validation_request.request, enhanced_context
            )
        else:
            # Use global security framework
            result = await security_framework.process_request(
                validation_request.request, enhanced_context
            )
        
        # Update metrics
        processing_time = (datetime.utcnow() - start_time).total_seconds() * 1000
        background_tasks.add_task(update_metrics, processing_time, False)
        
        return SecurityValidationResponse(
            success=True,
            request=result.get("request"),
            context=result.get("context"),
            security_metadata=result.get("security_metadata")
        )
        
    except SecurityError as e:
        # Security violation - block request
        processing_time = (datetime.utcnow() - start_time).total_seconds() * 1000
        background_tasks.add_task(update_metrics, processing_time, True)
        
        error_code = "SECURITY_VIOLATION"
        if isinstance(e, ValidationError):
            error_code = "VALIDATION_ERROR"
        elif isinstance(e, AuthenticationError):
            error_code = "AUTHENTICATION_ERROR"
        elif isinstance(e, AuthorizationError):
            error_code = "AUTHORIZATION_ERROR"
        elif isinstance(e, RateLimitError):
            error_code = "RATE_LIMIT_ERROR"
        
        return SecurityValidationResponse(
            success=False,
            error=str(e),
            error_code=error_code
        )
        
    except Exception as e:
        # Unexpected error
        processing_time = (datetime.utcnow() - start_time).total_seconds() * 1000
        background_tasks.add_task(update_metrics, processing_time, True)
        
        logger.error(f"Unexpected error in validation: {e}")
        return SecurityValidationResponse(
            success=False,
            error="Internal server error",
            error_code="INTERNAL_ERROR"
        )

@app.post("/batch-validate")
async def batch_validate(
    requests: list[SecurityValidationRequest],
    background_tasks: BackgroundTasks,
    request: Request,
    user: Dict[str, Any] = Depends(verify_api_key)
):
    """Validate multiple MCP requests in batch"""
    if len(requests) > 100:  # Limit batch size
        raise HTTPException(status_code=400, detail="Batch size too large (max 100)")
    
    results = []
    for req in requests:
        # Process each request individually
        result = await validate_request(req, background_tasks, request, user)
        results.append(result)
    
    return {"results": results}

@app.get("/config")
async def get_config(user: Dict[str, Any] = Depends(verify_api_key)):
    """Get current security configuration"""
    if not security_framework:
        raise HTTPException(status_code=500, detail="Security framework not initialized")
    
    config = security_framework.config
    return {
        "validation_strictness": config.validation_strictness,
        "enable_mfa": config.enable_mfa,
        "enable_rbac": config.enable_rbac,
        "enable_rate_limiting": config.enable_rate_limiting,
        "default_rate_limit": config.default_rate_limit,
        "enable_encryption": config.enable_encryption,
        "enable_ai_immune": config.enable_ai_immune,
        "anomaly_threshold": config.anomaly_threshold,
        "enable_audit_logging": config.enable_audit_logging,
        "log_level": config.log_level
    }

@app.get("/demo")
async def demo_endpoint():
    """Demo endpoint with example usage"""
    return {
        "message": "SMCP Security API Demo",
        "example_request": {
            "url": "/validate",
            "method": "POST",
            "headers": {
                "Authorization": "Bearer your_api_key",
                "Content-Type": "application/json"
            },
            "body": {
                "request": {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/list",
                    "params": {}
                },
                "context": {
                    "user_id": "user123",
                    "ip_address": "192.168.1.100"
                }
            }
        },
        "api_keys": {
            "demo": "demo_key_123",
            "test": "test_key_456"
        },
        "documentation": "/docs"
    }

def update_metrics(processing_time_ms: float, was_blocked: bool):
    """Update service metrics"""
    metrics["requests_processed"] += 1
    if was_blocked:
        metrics["requests_blocked"] += 1
    
    metrics["processing_times"].append(processing_time_ms)
    # Keep only last 1000 processing times
    if len(metrics["processing_times"]) > 1000:
        metrics["processing_times"] = metrics["processing_times"][-1000:]

# Exception handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "timestamp": datetime.utcnow().isoformat()
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "status_code": 500,
            "timestamp": datetime.utcnow().isoformat()
        }
    )

if __name__ == "__main__":
    # For local development
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=port,
        reload=False,
        log_level="info"
    )
