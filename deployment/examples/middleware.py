#!/usr/bin/env python3
"""SMCP Security Middleware

Easy-to-use middleware for integrating SMCP security into existing applications.
"""

import asyncio
import time
from typing import Dict, Any, Optional, Callable, Awaitable
from datetime import datetime

from fastapi import Request, Response, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from smcp_security import (
    SMCPSecurityFramework,
    SecurityConfig,
    SecurityError,
    ValidationError,
    AuthenticationError,
    AuthorizationError,
    RateLimitError
)


class SMCPMiddleware(BaseHTTPMiddleware):
    """SMCP Security Middleware for FastAPI/Starlette applications
    
    This middleware automatically applies SMCP security to MCP requests.
    
    Usage:
        app.add_middleware(SMCPMiddleware, config=security_config)
    """
    
    def __init__(
        self,
        app: ASGIApp,
        config: Optional[SecurityConfig] = None,
        mcp_paths: Optional[list] = None,
        skip_paths: Optional[list] = None,
        user_extractor: Optional[Callable] = None,
        error_handler: Optional[Callable] = None
    ):
        super().__init__(app)
        
        # Initialize security framework
        self.security = SMCPSecurityFramework(config or SecurityConfig())
        
        # Configure paths
        self.mcp_paths = mcp_paths or ['/mcp', '/api/mcp']
        self.skip_paths = skip_paths or ['/health', '/docs', '/openapi.json', '/favicon.ico']
        
        # Custom functions
        self.user_extractor = user_extractor or self._default_user_extractor
        self.error_handler = error_handler or self._default_error_handler
        
        # Metrics
        self.metrics = {
            'requests_processed': 0,
            'requests_blocked': 0,
            'processing_times': [],
            'start_time': datetime.utcnow()
        }
    
    async def dispatch(self, request: Request, call_next) -> Response:
        """Process request through SMCP security middleware"""
        start_time = time.time()
        
        # Skip non-MCP paths
        if not self._should_process_request(request):
            return await call_next(request)
        
        try:
            # Extract user context
            user_context = await self.user_extractor(request)
            
            # Read request body
            body = await request.body()
            if not body:
                return await call_next(request)
            
            # Parse JSON request
            import json
            try:
                mcp_request = json.loads(body)
            except json.JSONDecodeError:
                return await call_next(request)
            
            # Prepare context
            context = {
                'user_id': user_context.get('user_id', 'anonymous'),
                'ip_address': request.client.host,
                'user_agent': request.headers.get('user-agent', 'unknown'),
                'path': str(request.url.path),
                'method': request.method,
                'timestamp': datetime.utcnow().isoformat(),
                **user_context
            }
            
            # Process through security framework
            security_result = await self.security.process_request(mcp_request, context)
            
            # Replace request body with validated request
            validated_request = security_result['request']
            validated_body = json.dumps(validated_request).encode()
            
            # Create new request with validated body
            request._body = validated_body
            
            # Continue to application
            response = await call_next(request)
            
            # Add security headers to response
            self._add_security_headers(response, security_result)
            
            # Update metrics
            processing_time = (time.time() - start_time) * 1000
            self._update_metrics(processing_time, False)
            
            return response
            
        except SecurityError as e:
            # Security violation - block request
            processing_time = (time.time() - start_time) * 1000
            self._update_metrics(processing_time, True)
            
            return await self.error_handler(request, e)
            
        except Exception as e:
            # Unexpected error - log and continue
            processing_time = (time.time() - start_time) * 1000
            self._update_metrics(processing_time, True)
            
            # In case of error, continue without security (fail open)
            # In production, you might want to fail closed
            return await call_next(request)
    
    def _should_process_request(self, request: Request) -> bool:
        """Determine if request should be processed by SMCP security"""
        path = str(request.url.path)
        
        # Skip certain paths
        if any(skip_path in path for skip_path in self.skip_paths):
            return False
        
        # Only process MCP paths
        if self.mcp_paths:
            return any(mcp_path in path for mcp_path in self.mcp_paths)
        
        # Process all requests by default
        return True
    
    async def _default_user_extractor(self, request: Request) -> Dict[str, Any]:
        """Default user context extractor"""
        # Try to extract from Authorization header
        auth_header = request.headers.get('authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
            try:
                payload = self.security.jwt_auth.verify_token(token)
                return {
                    'user_id': payload.get('user_id', 'anonymous'),
                    'roles': payload.get('roles', []),
                    'permissions': payload.get('permissions', [])
                }
            except Exception:
                pass
        
        # Default anonymous user
        return {
            'user_id': 'anonymous',
            'roles': ['guest'],
            'permissions': ['mcp:read']
        }
    
    async def _default_error_handler(self, request: Request, error: SecurityError) -> Response:
        """Default error handler for security violations"""
        error_code = 403
        error_type = "SECURITY_ERROR"
        
        if isinstance(error, ValidationError):
            error_type = "VALIDATION_ERROR"
        elif isinstance(error, AuthenticationError):
            error_code = 401
            error_type = "AUTHENTICATION_ERROR"
        elif isinstance(error, AuthorizationError):
            error_code = 403
            error_type = "AUTHORIZATION_ERROR"
        elif isinstance(error, RateLimitError):
            error_code = 429
            error_type = "RATE_LIMIT_ERROR"
        
        return JSONResponse(
            status_code=error_code,
            content={
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32000,
                    "message": str(error),
                    "data": {
                        "type": error_type,
                        "timestamp": datetime.utcnow().isoformat()
                    }
                }
            }
        )
    
    def _add_security_headers(self, response: Response, security_result: Dict[str, Any]):
        """Add security headers to response"""
        metadata = security_result.get('security_metadata', {})
        
        response.headers['X-SMCP-Security-Level'] = metadata.get('security_level', 'unknown')
        response.headers['X-SMCP-Processing-Time'] = str(metadata.get('processing_time_ms', 0))
        response.headers['X-SMCP-Version'] = '1.0.0'
        
        # Standard security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
    
    def _update_metrics(self, processing_time_ms: float, was_blocked: bool):
        """Update middleware metrics"""
        self.metrics['requests_processed'] += 1
        if was_blocked:
            self.metrics['requests_blocked'] += 1
        
        self.metrics['processing_times'].append(processing_time_ms)
        # Keep only last 1000 processing times
        if len(self.metrics['processing_times']) > 1000:
            self.metrics['processing_times'] = self.metrics['processing_times'][-1000:]
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get middleware metrics"""
        uptime = (datetime.utcnow() - self.metrics['start_time']).total_seconds()
        avg_processing_time = (
            sum(self.metrics['processing_times']) / len(self.metrics['processing_times'])
            if self.metrics['processing_times'] else 0.0
        )
        
        return {
            'requests_processed': self.metrics['requests_processed'],
            'requests_blocked': self.metrics['requests_blocked'],
            'block_rate': (
                self.metrics['requests_blocked'] / self.metrics['requests_processed']
                if self.metrics['requests_processed'] > 0 else 0.0
            ),
            'average_processing_time_ms': avg_processing_time,
            'uptime_seconds': uptime
        }


class SMCPSecurityDecorator:
    """Decorator for adding SMCP security to individual functions
    
    Usage:
        @smcp_security.secure
        async def my_mcp_handler(request, context):
            return result
    """
    
    def __init__(self, config: Optional[SecurityConfig] = None):
        self.security = SMCPSecurityFramework(config or SecurityConfig())
    
    def secure(self, func: Callable) -> Callable:
        """Decorator to add SMCP security to a function"""
        async def wrapper(*args, **kwargs):
            # Extract request and context from arguments
            request = kwargs.get('request') or (args[0] if args else None)
            context = kwargs.get('context') or (args[1] if len(args) > 1 else {})
            
            if not request:
                raise ValueError("Request parameter required for SMCP security")
            
            # Process through security framework
            security_result = await self.security.process_request(request, context)
            
            # Update arguments with validated request
            if 'request' in kwargs:
                kwargs['request'] = security_result['request']
                kwargs['context'] = security_result['context']
            else:
                args = list(args)
                args[0] = security_result['request']
                if len(args) > 1:
                    args[1] = security_result['context']
                args = tuple(args)
            
            # Call original function
            result = await func(*args, **kwargs)
            
            # Add security metadata to result
            if isinstance(result, dict):
                result['security_metadata'] = security_result['security_metadata']
            
            return result
        
        return wrapper


# Global decorator instance
smcp_security = SMCPSecurityDecorator()


# Example usage functions
def create_secure_app(app_factory: Callable, security_config: Optional[SecurityConfig] = None):
    """Create a secure FastAPI app with SMCP middleware"""
    app = app_factory()
    
    # Add SMCP security middleware
    app.add_middleware(SMCPMiddleware, config=security_config)
    
    # Add metrics endpoint
    @app.get('/security/metrics')
    async def get_security_metrics(request: Request):
        # Find SMCP middleware
        for middleware in app.user_middleware:
            if isinstance(middleware.cls, type) and issubclass(middleware.cls, SMCPMiddleware):
                return middleware.cls.get_metrics()
        return {'error': 'SMCP middleware not found'}
    
    return app


if __name__ == '__main__':
    # Demo usage
    from fastapi import FastAPI
    
    def create_demo_app():
        app = FastAPI(title="Demo App with SMCP Security")
        
        @app.post('/mcp')
        async def mcp_handler(request: dict):
            return {'result': 'success', 'request': request}
        
        return app
    
    # Create secure app
    app = create_secure_app(create_demo_app)
    
    print("Demo app created with SMCP security middleware")
    print("Run with: uvicorn middleware:app --reload")
