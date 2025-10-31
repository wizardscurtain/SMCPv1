#!/usr/bin/env python3
"""FastAPI integration example for SMCP Security"""

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any

from smcp_security import SMCPSecurityFramework, SecurityConfig
from smcp_security.middleware import SMCPSecurityMiddleware, get_user_context_dependency
from smcp_security.exceptions import SecurityError, AuthenticationError


# Pydantic models
class MCPRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: str
    method: str
    params: Optional[Dict[str, Any]] = None


class LoginRequest(BaseModel):
    username: str
    password: str
    mfa_code: Optional[str] = None


class MCPResponse(BaseModel):
    jsonrpc: str = "2.0"
    id: str
    result: Optional[Dict[str, Any]] = None
    error: Optional[Dict[str, Any]] = None


# Initialize FastAPI app
app = FastAPI(
    title="SMCP Secure MCP Server",
    description="Model Context Protocol server with SMCP security",
    version="1.0.0"
)

# Configure SMCP Security
security_config = SecurityConfig(
    enable_mfa=True,
    validation_strictness="maximum",
    enable_ai_immune=True,
    anomaly_threshold=0.8,
    default_rate_limit=100,
    enable_audit_logging=True
)

security = SMCPSecurityFramework(config=security_config)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add SMCP security middleware
app.add_middleware(SMCPSecurityMiddleware, security_framework=security)

# Dependency for getting user context
get_user_context = get_user_context_dependency(security)


@app.get("/health")
async def health_check():
    """Health check endpoint (bypasses security)"""
    return {"status": "healthy", "timestamp": time.time()}


@app.post("/auth/login")
async def login(request: LoginRequest):
    """User authentication endpoint"""
    try:
        # Validate credentials (implement your own logic)
        if request.username == "demo" and request.password == "password":
            # Create secure session
            token = security.create_user_session(
                user_id=request.username,
                mfa_code=request.mfa_code
            )
            
            return {
                "access_token": token,
                "token_type": "bearer",
                "expires_in": security.config.jwt_expiry_seconds
            }
        else:
            raise HTTPException(status_code=401, detail="Invalid credentials")
            
    except AuthenticationError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail="Authentication failed")


@app.post("/mcp/request", response_model=MCPResponse)
async def handle_mcp_request(
    request: MCPRequest,
    user_context: Optional[dict] = Depends(get_user_context)
):
    """Handle MCP requests with security validation"""
    try:
        # Request is automatically validated by middleware
        # Process based on method
        if request.method == "tools/list":
            result = await list_tools(user_context)
        elif request.method == "tools/call":
            result = await call_tool(request.params, user_context)
        elif request.method == "resources/list":
            result = await list_resources(user_context)
        elif request.method == "resources/read":
            result = await read_resource(request.params, user_context)
        elif request.method == "prompts/list":
            result = await list_prompts(user_context)
        elif request.method == "prompts/get":
            result = await get_prompt(request.params, user_context)
        else:
            raise HTTPException(status_code=400, detail=f"Unknown method: {request.method}")
        
        return MCPResponse(id=request.id, result=result)
        
    except SecurityError as e:
        return MCPResponse(
            id=request.id,
            error={"code": -32600, "message": f"Security error: {str(e)}"}
        )
    except Exception as e:
        return MCPResponse(
            id=request.id,
            error={"code": -32603, "message": f"Internal error: {str(e)}"}
        )


# MCP method implementations
async def list_tools(user_context: Optional[dict]) -> Dict[str, Any]:
    """List available tools"""
    # Check permissions
    if user_context and not security.authorize_action(
        user_context.get('user_id'), 'tools:list'
    ):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    return {
        "tools": [
            {
                "name": "calculator",
                "description": "Perform mathematical calculations",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "expression": {"type": "string"}
                    },
                    "required": ["expression"]
                }
            },
            {
                "name": "weather",
                "description": "Get weather information",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "location": {"type": "string"}
                    },
                    "required": ["location"]
                }
            }
        ]
    }


async def call_tool(params: Dict[str, Any], user_context: Optional[dict]) -> Dict[str, Any]:
    """Call a specific tool"""
    if not params or 'name' not in params:
        raise HTTPException(status_code=400, detail="Tool name required")
    
    tool_name = params['name']
    
    # Check permissions
    if user_context and not security.authorize_action(
        user_context.get('user_id'), f'tools:call:{tool_name}'
    ):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    # Implement tool logic
    if tool_name == "calculator":
        expression = params.get('arguments', {}).get('expression', '')
        # Safely evaluate mathematical expressions
        try:
            # In production, use a safe math evaluator
            result = eval(expression)  # WARNING: Don't use eval in production!
            return {"content": [{"type": "text", "text": str(result)}]}
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Calculation error: {e}")
    
    elif tool_name == "weather":
        location = params.get('arguments', {}).get('location', '')
        # Mock weather data
        return {
            "content": [{
                "type": "text",
                "text": f"Weather in {location}: 22°C, Sunny"
            }]
        }
    
    else:
        raise HTTPException(status_code=404, detail=f"Tool not found: {tool_name}")


async def list_resources(user_context: Optional[dict]) -> Dict[str, Any]:
    """List available resources"""
    return {"resources": []}


async def read_resource(params: Dict[str, Any], user_context: Optional[dict]) -> Dict[str, Any]:
    """Read a specific resource"""
    return {"contents": []}


async def list_prompts(user_context: Optional[dict]) -> Dict[str, Any]:
    """List available prompts"""
    return {"prompts": []}


async def get_prompt(params: Dict[str, Any], user_context: Optional[dict]) -> Dict[str, Any]:
    """Get a specific prompt"""
    return {"messages": []}


@app.get("/security/metrics")
async def get_security_metrics(user_context: Optional[dict] = Depends(get_user_context)):
    """Get security metrics (admin only)"""
    if not user_context or user_context.get('role') != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    
    return security.get_security_metrics()


@app.get("/security/audit")
async def get_audit_logs(
    limit: int = 100,
    user_context: Optional[dict] = Depends(get_user_context)
):
    """Get audit logs (admin only)"""
    if not user_context or user_context.get('role') != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    
    return security.audit_logger.get_recent_logs(limit=limit)


if __name__ == "__main__":
    import uvicorn
    import time
    
    print("Starting SMCP Secure MCP Server...")
    print("Security features enabled:")
    print(f"  - Input Validation: {security.config.enable_input_validation}")
    print(f"  - MFA: {security.config.enable_mfa}")
    print(f"  - RBAC: {security.config.enable_rbac}")
    print(f"  - Rate Limiting: {security.config.enable_rate_limiting}")
    print(f"  - AI Immune System: {security.config.enable_ai_immune}")
    print(f"  - Audit Logging: {security.config.enable_audit_logging}")
    
    uvicorn.run(
        "fastapi_example:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
