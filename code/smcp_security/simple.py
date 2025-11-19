"""Simple integration helpers for SMCP - "HTTPS for MCP"

This module provides dead-simple ways to add security to MCP servers:
1. @security.protect decorator
2. secure_mcp(server) one-liner
3. Sensible defaults that work out of box
"""

import functools
from typing import Any, Callable, Optional, Dict
from .core import SMCPSecurityFramework, SecurityConfig


# Global default security instance for simple usage
_default_security: Optional[SMCPSecurityFramework] = None


def get_default_security() -> SMCPSecurityFramework:
    """Get or create the default security instance with sensible defaults."""
    global _default_security
    if _default_security is None:
        config = SecurityConfig(
            # Sensible defaults for immediate protection
            enable_input_validation=True,
            validation_strictness="standard",  # Not too strict to start
            enable_rate_limiting=True,
            default_rate_limit=100,  # 100 req/min per user
            enable_ai_immune=True,
            anomaly_threshold=0.8,  # Slightly permissive to avoid false positives
            enable_audit_logging=True,
            log_level="INFO",
            # Optional features disabled by default
            enable_mfa=False,  # User can enable if needed
            enable_rbac=False,  # User can enable if needed
        )
        _default_security = SMCPSecurityFramework(config)
    return _default_security


def protect(func: Callable) -> Callable:
    """Decorator to protect an MCP tool with SMCP security.

    Usage:
        @server.call_tool()
        @protect
        async def dangerous_tool(arguments):
            return execute(arguments)

    This will:
    - Validate inputs (command injection, XSS, SQL injection, etc.)
    - Check rate limits
    - Detect prompt injection attempts
    - Log security events
    - Block malicious requests
    """
    security = get_default_security()

    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        # Extract request data from args/kwargs
        # MCP tools typically get arguments dict as first parameter
        request_data = args[0] if args else kwargs.get('arguments', {})

        # Validate the request through security framework
        try:
            # Process request through all security layers
            validated = await security.process_request(
                request_data={"params": request_data},
                user_context=kwargs.get('user_context', {})
            )

            # Call the original function with validated data
            return await func(*args, **kwargs)

        except Exception as e:
            # Security violation - log and reject
            security.audit_logger.log_event(
                category="SECURITY_VIOLATION",
                severity="HIGH",
                message=f"Security check failed for {func.__name__}: {str(e)}",
                details={"function": func.__name__, "error": str(e)}
            )
            raise

    return wrapper


def secure_mcp(server: Any, config: Optional[SecurityConfig] = None) -> Any:
    """One-liner to add SMCP security to any MCP server.

    Usage:
        from mcp.server import Server
        from smcp_security import secure_mcp

        server = Server("my-tools")
        server = secure_mcp(server)  # That's it!

    Or with custom config:
        config = SecurityConfig(default_rate_limit=200)
        server = secure_mcp(server, config)

    This automatically wraps all tool handlers with security checks.
    """
    security = SMCPSecurityFramework(config) if config else get_default_security()

    # Store original tool registration method
    if hasattr(server, 'call_tool'):
        original_call_tool = server.call_tool

        def secure_call_tool():
            """Wrapper that adds @protect to all registered tools."""
            def decorator(func):
                # Apply protection decorator
                protected_func = protect(func)
                # Register with original method
                return original_call_tool()(protected_func)
            return decorator

        # Replace with secure version
        server.call_tool = secure_call_tool

    # Store reference to security framework on server
    server._smcp_security = security

    return server


class SMCPMiddleware:
    """SMCP middleware for frameworks that support middleware pattern.

    Usage with FastAPI:
        from fastapi import FastAPI
        from smcp_security import SMCPMiddleware

        app = FastAPI()
        app.add_middleware(SMCPMiddleware)

    Usage with FastMCP:
        from fastmcp import FastMCP
        from smcp_security import SMCPMiddleware

        mcp = FastMCP("my-server")
        mcp.add_middleware(SMCPMiddleware)
    """

    def __init__(self, app, config: Optional[SecurityConfig] = None):
        self.app = app
        self.security = SMCPSecurityFramework(config) if config else get_default_security()

    async def __call__(self, scope, receive, send):
        """ASGI middleware implementation."""
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        # Extract request data
        request_data = scope

        try:
            # Validate through security framework
            await self.security.process_request(
                request_data=request_data,
                user_context=scope.get('user', {})
            )

            # Continue to app
            return await self.app(scope, receive, send)

        except Exception as e:
            # Security violation - return 403
            self.security.audit_logger.log_event(
                category="SECURITY_VIOLATION",
                severity="HIGH",
                message=f"Security check failed: {str(e)}",
                details={"path": scope.get('path'), "error": str(e)}
            )

            # Return 403 Forbidden
            await send({
                'type': 'http.response.start',
                'status': 403,
                'headers': [(b'content-type', b'application/json')],
            })
            await send({
                'type': 'http.response.body',
                'body': b'{"error": "Security violation detected"}',
            })


# Convenience exports for easy imports
__all__ = [
    'protect',
    'secure_mcp',
    'SMCPMiddleware',
    'get_default_security',
    'SecurityConfig',
    'SMCPSecurityFramework',
]
