#!/usr/bin/env python3
"""FastAPI Integration Example for SMCP Security Framework

This example shows how to integrate SMCPv1 security into a FastAPI-based MCP server.
"""

import asyncio
from typing import Dict, Any, Optional
from datetime import datetime

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

# Import SMCP Security Framework
from smcp_security import (
    SMCPSecurityFramework,
    SecurityConfig,
    SecurityError
)

# Security bearer token
security = HTTPBearer()

# Request/Response models
class MCPRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: Optional[int] = None
    method: str
    params: Optional[Dict[str, Any]] = None

class MCPResponse(BaseModel):
    jsonrpc: str = "2.0"
    id: Optional[int] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[Dict[str, Any]] = None

# Initialize FastAPI app
app = FastAPI(
    title="Secure MCP Server",
    description="MCP Server with SMCPv1 Security Framework",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize SMCP Security Framework
security_config = SecurityConfig(
    enable_input_validation=True,
    validation_strictness="standard",
    enable_mfa=False,  # Disabled for demo
    enable_rbac=True,
    enable_rate_limiting=True,
    default_rate_limit=100,
    enable_encryption=True,
    enable_ai_immune=True,
    anomaly_threshold=0.8,
    enable_audit_logging=True,
    log_level="INFO"
)

smcp_security = SMCPSecurityFramework(security_config)

# Demo tools
tools = {
    "echo": {
        "description": "Echo the input message",
        "parameters": {
            "type": "object",
            "properties": {
                "message": {"type": "string", "description": "Message to echo"}
            },
            "required": ["message"]
        }
    },
    "calculate": {
        "description": "Perform basic calculations",
        "parameters": {
            "type": "object",
            "properties": {
                "expression": {"type": "string", "description": "Mathematical expression"}
            },
            "required": ["expression"]
        }
    },
    "get_time": {
        "description": "Get current time",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    }
}

# Setup demo users and roles
def setup_demo_security():
    """Setup demo users and roles for testing"""
    rbac = smcp_security.rbac_manager
    
    # Define roles
    rbac.define_role("guest", [
        "mcp:read",
        "mcp:execute:echo",
        "mcp:execute:get_time"
    ], "Guest user with limited access")
    
    rbac.define_role("user", [
        "mcp:read",
        "mcp:execute:echo",
        "mcp:execute:calculate",
        "mcp:execute:get_time"
    ], "Regular user")
    
    rbac.define_role("admin", [
        "mcp:*"
    ], "Administrator with full access")
    
    # Assign roles to demo users
    rbac.assign_role("demo_guest", "guest")
    rbac.assign_role("demo_user", "user")
    rbac.assign_role("demo_admin", "admin")

# Initialize security on startup
@app.on_event("startup")
async def startup_event():
    setup_demo_security()
    print("🛡️ SMCP Security Framework initialized")
    print("📋 Demo users created: demo_guest, demo_user, demo_admin")

# Authentication dependency
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Extract user from JWT token"""
    try:
        token = credentials.credentials
        payload = smcp_security.jwt_auth.verify_token(token)
        return payload
    except Exception:
        # For demo, allow anonymous access with guest role
        return {
            "user_id": "anonymous",
            "roles": ["guest"],
            "permissions": ["mcp:read", "mcp:execute:echo", "mcp:execute:get_time"]
        }

# Create demo token endpoint
@app.post("/auth/token")
async def create_token(user_data: Dict[str, str]):
    """Create demo authentication token"""
    user_id = user_data.get("user_id", "demo_guest")
    
    # Get user roles and permissions
    user_roles = smcp_security.rbac_manager.get_user_roles(user_id)
    user_permissions = smcp_security.rbac_manager.get_user_permissions(user_id)
    
    if not user_roles:
        # Default to guest if user not found
        user_roles = ["guest"]
        user_permissions = ["mcp:read", "mcp:execute:echo", "mcp:execute:get_time"]
    
    token = smcp_security.jwt_auth.generate_token(
        user_id=user_id,
        roles=user_roles,
        permissions=user_permissions,
        mfa_verified=True  # Skip MFA for demo
    )
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user_id": user_id,
        "roles": user_roles,
        "permissions": user_permissions
    }

# Main MCP endpoint with security
@app.post("/mcp", response_model=MCPResponse)
async def handle_mcp_request(
    mcp_request: MCPRequest,
    request: Request,
    user: Dict[str, Any] = Depends(get_current_user)
):
    """Handle MCP requests with security validation"""
    try:
        # Prepare context
        context = {
            "user_id": user.get("user_id", "anonymous"),
            "roles": user.get("roles", []),
            "permissions": user.get("permissions", []),
            "ip_address": request.client.host,
            "user_agent": request.headers.get("user-agent", "unknown"),
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Process through security framework
        security_result = await smcp_security.process_request(
            mcp_request.dict(), context
        )
        
        validated_request = security_result["request"]
        auth_context = security_result["context"]
        
        # Route to appropriate handler
        method = validated_request.get("method")
        
        if method == "tools/list":
            result = await handle_tools_list(auth_context)
        elif method == "tools/call":
            params = validated_request.get("params", {})
            result = await handle_tools_call(params, auth_context)
        else:
            result = {
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {method}"
                }
            }
        
        # Add security metadata
        if "result" in result:
            result["security_metadata"] = security_result["security_metadata"]
        
        return MCPResponse(
            id=mcp_request.id,
            **result
        )
        
    except SecurityError as e:
        return MCPResponse(
            id=mcp_request.id,
            error={
                "code": -32000,
                "message": f"Security error: {str(e)}"
            }
        )
    except Exception as e:
        return MCPResponse(
            id=mcp_request.id,
            error={
                "code": -32603,
                "message": f"Internal error: {str(e)}"
            }
        )

async def handle_tools_list(auth_context: Dict[str, Any]) -> Dict[str, Any]:
    """Handle tools/list request"""
    user_id = auth_context.get("user_id")
    available_tools = []
    
    for tool_name, tool_info in tools.items():
        # Check if user has permission for this tool
        if smcp_security.rbac_manager.check_permission(
            user_id, f"mcp:execute:{tool_name}"
        ):
            available_tools.append({
                "name": tool_name,
                "description": tool_info["description"],
                "inputSchema": tool_info["parameters"]
            })
    
    return {"result": {"tools": available_tools}}

async def handle_tools_call(params: Dict[str, Any], auth_context: Dict[str, Any]) -> Dict[str, Any]:
    """Handle tools/call request"""
    tool_name = params.get("name")
    tool_arguments = params.get("arguments", {})
    user_id = auth_context.get("user_id")
    
    # Check permission
    if not smcp_security.rbac_manager.check_permission(
        user_id, f"mcp:execute:{tool_name}"
    ):
        return {
            "error": {
                "code": -32000,
                "message": f"Permission denied for tool: {tool_name}"
            }
        }
    
    # Execute tool
    if tool_name == "echo":
        message = tool_arguments.get("message", "Hello, World!")
        return {
            "result": {
                "content": [{
                    "type": "text",
                    "text": f"Echo: {message}"
                }]
            }
        }
    
    elif tool_name == "calculate":
        expression = tool_arguments.get("expression", "1+1")
        
        # Basic validation to prevent code injection
        allowed_chars = set("0123456789+-*/()., ")
        if not all(c in allowed_chars for c in expression):
            return {
                "error": {
                    "code": -32000,
                    "message": "Invalid characters in expression"
                }
            }
        
        try:
            result = eval(expression)  # Note: Use safe math parser in production
            return {
                "result": {
                    "content": [{
                        "type": "text",
                        "text": f"Result: {expression} = {result}"
                    }]
                }
            }
        except Exception as e:
            return {
                "error": {
                    "code": -32000,
                    "message": f"Calculation error: {str(e)}"
                }
            }
    
    elif tool_name == "get_time":
        current_time = datetime.utcnow().isoformat()
        return {
            "result": {
                "content": [{
                    "type": "text",
                    "text": f"Current UTC time: {current_time}"
                }]
            }
        }
    
    else:
        return {
            "error": {
                "code": -32000,
                "message": f"Tool not found: {tool_name}"
            }
        }

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "security_framework": "active",
        "version": "1.0.0"
    }

# Security metrics endpoint
@app.get("/security/metrics")
async def security_metrics(user: Dict[str, Any] = Depends(get_current_user)):
    """Get security metrics"""
    # Check admin permission
    if not smcp_security.rbac_manager.check_permission(
        user.get("user_id"), "system:metrics"
    ):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    return smcp_security.get_security_metrics()

# Demo endpoint
@app.get("/demo")
async def demo_info():
    """Demo information and usage examples"""
    return {
        "message": "SMCP Security Framework - FastAPI Integration Demo",
        "endpoints": {
            "auth": "/auth/token",
            "mcp": "/mcp",
            "health": "/health",
            "metrics": "/security/metrics",
            "docs": "/docs"
        },
        "demo_users": {
            "guest": "demo_guest",
            "user": "demo_user", 
            "admin": "demo_admin"
        },
        "example_usage": {
            "1_get_token": {
                "method": "POST",
                "url": "/auth/token",
                "body": {"user_id": "demo_user"}
            },
            "2_list_tools": {
                "method": "POST",
                "url": "/mcp",
                "headers": {"Authorization": "Bearer <token>"},
                "body": {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/list"
                }
            },
            "3_call_tool": {
                "method": "POST",
                "url": "/mcp",
                "headers": {"Authorization": "Bearer <token>"},
                "body": {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "echo",
                        "arguments": {"message": "Hello SMCP!"}
                    }
                }
            }
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
