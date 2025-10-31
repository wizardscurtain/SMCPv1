"""Middleware implementations for popular Python web frameworks"""

import json
import time
from typing import Callable, Any, Optional
from fastapi import Request, Response, HTTPException
from fastapi.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from .core import SMCPSecurityFramework
from .exceptions import SecurityError, AuthenticationError, AuthorizationError, RateLimitError


class SMCPSecurityMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware for SMCP security"""
    
    def __init__(self, app, security_framework: SMCPSecurityFramework):
        super().__init__(app)
        self.security = security_framework
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request through security framework"""
        start_time = time.time()
        
        try:
            # Skip security for health checks and static files
            if self._should_skip_security(request):
                return await call_next(request)
            
            # Extract and validate request data
            request_data = await self._extract_request_data(request)
            
            # Apply security validations
            await self._apply_security_checks(request, request_data)
            
            # Process the request
            response = await call_next(request)
            
            # Log successful request
            self.security.audit_logger.log_request(
                request_data=request_data,
                response_status=response.status_code,
                processing_time=time.time() - start_time,
                user_id=getattr(request.state, 'user_id', None)
            )
            
            return response
            
        except SecurityError as e:
            return self._create_error_response(e, 403)
        except AuthenticationError as e:
            return self._create_error_response(e, 401)
        except AuthorizationError as e:
            return self._create_error_response(e, 403)
        except RateLimitError as e:
            return self._create_error_response(e, 429)
        except Exception as e:
            self.security.audit_logger.log_error(
                error=str(e),
                request_data=request_data if 'request_data' in locals() else None
            )
            return self._create_error_response(e, 500)
    
    def _should_skip_security(self, request: Request) -> bool:
        """Check if security should be skipped for this request"""
        skip_paths = ['/health', '/metrics', '/static', '/favicon.ico']
        return any(request.url.path.startswith(path) for path in skip_paths)
    
    async def _extract_request_data(self, request: Request) -> dict:
        """Extract request data for validation"""
        data = {
            'method': request.method,
            'path': request.url.path,
            'headers': dict(request.headers),
            'query_params': dict(request.query_params)
        }
        
        # Add body for POST/PUT requests
        if request.method in ['POST', 'PUT', 'PATCH']:
            try:
                body = await request.body()
                if body:
                    data['body'] = json.loads(body.decode('utf-8'))
            except (json.JSONDecodeError, UnicodeDecodeError):
                data['body'] = body.decode('utf-8', errors='ignore')
        
        return data
    
    async def _apply_security_checks(self, request: Request, request_data: dict):
        """Apply all security validations"""
        # Input validation
        validated_data = self.security.validate_request(request_data)
        
        # Authentication
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header[7:]
            user_context = self.security.authenticate_token(token)
            request.state.user_id = user_context.get('user_id')
            request.state.user_context = user_context
        
        # Rate limiting
        client_ip = request.client.host
        user_id = getattr(request.state, 'user_id', client_ip)
        
        if not self.security.rate_limiter.is_allowed(user_id):
            raise RateLimitError("Rate limit exceeded")
        
        # Authorization (if user is authenticated)
        if hasattr(request.state, 'user_id'):
            action = f"{request.method}:{request.url.path}"
            if not self.security.authorize_action(request.state.user_id, action):
                raise AuthorizationError(f"Access denied for action: {action}")
    
    def _create_error_response(self, error: Exception, status_code: int) -> JSONResponse:
        """Create standardized error response"""
        return JSONResponse(
            status_code=status_code,
            content={
                'error': type(error).__name__,
                'message': str(error),
                'timestamp': time.time()
            }
        )


class SMCPFlaskMiddleware:
    """Flask middleware for SMCP security"""
    
    def __init__(self, app, security_framework: SMCPSecurityFramework):
        self.app = app
        self.security = security_framework
    
    def __call__(self, environ, start_response):
        """WSGI middleware implementation"""
        # This is a simplified implementation
        # In practice, you'd want to use Flask's request context
        return self.app(environ, start_response)


def get_user_context_dependency(security: SMCPSecurityFramework):
    """FastAPI dependency for getting user context"""
    def get_user_context(request: Request) -> Optional[dict]:
        return getattr(request.state, 'user_context', None)
    
    return get_user_context
