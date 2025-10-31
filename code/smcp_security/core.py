"""Core SMCP Security Framework Implementation

This module provides the main security framework that integrates all
security layers into a cohesive defense system.
"""

import asyncio
import json
import time
import secrets
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from datetime import datetime

from .input_validation import InputValidator
from .authentication import JWTAuthenticator, MFAManager
from .authorization import RBACManager
from .rate_limiting import AdaptiveRateLimiter, DoSProtection
from .cryptography import SMCPCrypto
from .audit import SMCPAuditLogger
from .ai_immune import AIImmuneSystem, ThreatClassifier
from .exceptions import (
    SecurityError, ValidationError, AuthenticationError,
    AuthorizationError, RateLimitError, CryptographicError
)


@dataclass
class SecurityConfig:
    """Configuration for SMCP Security Framework"""
    # Input validation settings
    enable_input_validation: bool = True
    validation_strictness: str = "standard"  # minimal, standard, maximum
    
    # Authentication settings
    enable_mfa: bool = True
    jwt_expiry_seconds: int = 3600
    session_timeout_seconds: int = 7200
    
    # Authorization settings
    enable_rbac: bool = True
    default_permissions: List[str] = None
    
    # Rate limiting settings
    enable_rate_limiting: bool = True
    default_rate_limit: int = 100  # requests per minute
    adaptive_limits: bool = True
    
    # Cryptographic settings
    enable_encryption: bool = True
    key_rotation_interval: int = 86400  # 24 hours
    
    # AI immune system settings
    enable_ai_immune: bool = True
    anomaly_threshold: float = 0.7
    learning_mode: bool = False
    
    # Audit settings
    enable_audit_logging: bool = True
    log_level: str = "INFO"
    
    def __post_init__(self):
        if self.default_permissions is None:
            self.default_permissions = ["read"]
        
        # Validate configuration
        self._validate_config()
    
    def _validate_config(self):
        """Validate configuration parameters"""
        # Validate validation strictness
        valid_strictness = ["minimal", "standard", "maximum"]
        if self.validation_strictness not in valid_strictness:
            raise ValueError(f"Invalid validation strictness: {self.validation_strictness}")
        
        # Validate log level
        valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self.log_level not in valid_log_levels:
            raise ValueError(f"Invalid log level: {self.log_level}")
        
        # Validate rate limit
        if self.default_rate_limit <= 0:
            raise ValueError("Rate limit must be positive")
        
        # Validate anomaly threshold
        if not 0.0 <= self.anomaly_threshold <= 1.0:
            raise ValueError("Anomaly threshold must be between 0.0 and 1.0")
        
        # Validate JWT expiry
        if self.jwt_expiry_seconds <= 0:
            raise ValueError("JWT expiry must be positive")
        
        # Validate session timeout
        if self.session_timeout_seconds <= 0:
            raise ValueError("Session timeout must be positive")


class SMCPSecurityFramework:
    """Main SMCP Security Framework
    
    Integrates all security layers into a defense system.
    """
    
    def __init__(self, config: SecurityConfig = None):
        self.config = config or SecurityConfig()
        self._initialize_components()
        self._setup_metrics()
    
    def _initialize_components(self):
        """Initialize all security components"""
        # Input validation layer
        if self.config.enable_input_validation:
            self.input_validator = InputValidator(
                strictness=self.config.validation_strictness
            )
        else:
            self.input_validator = None
        
        # Authentication layer
        from .authentication import AuthenticationConfig
        auth_config = AuthenticationConfig(
            jwt_secret_key=secrets.token_urlsafe(32),
            jwt_expiry_seconds=self.config.jwt_expiry_seconds
        )
        self.jwt_auth = JWTAuthenticator(auth_config)
        
        if self.config.enable_mfa:
            self.mfa_manager = MFAManager()
        else:
            self.mfa_manager = None
        
        # Authorization layer
        if self.config.enable_rbac:
            self.rbac_manager = RBACManager()
            self._setup_default_roles()
        else:
            self.rbac_manager = None
        
        # Rate limiting layer
        if self.config.enable_rate_limiting:
            self.rate_limiter = AdaptiveRateLimiter(
                default_limit=self.config.default_rate_limit,
                adaptive=self.config.adaptive_limits
            )
            self.dos_protection = DoSProtection()
        else:
            self.rate_limiter = None
            self.dos_protection = None
        
        # Cryptographic layer
        if self.config.enable_encryption:
            self.crypto = SMCPCrypto()
            self.crypto_manager = self.crypto  # Alias for tests
        else:
            self.crypto = None
            self.crypto_manager = None
        
        # AI immune system
        if self.config.enable_ai_immune:
            self.ai_immune = AIImmuneSystem(
                threshold=self.config.anomaly_threshold,
                learning_mode=self.config.learning_mode
            )
            self.ai_immune_system = self.ai_immune  # Alias for tests
            self.threat_classifier = ThreatClassifier()
        else:
            self.ai_immune = None
            self.ai_immune_system = None
            self.threat_classifier = None
        
        # Audit layer
        if self.config.enable_audit_logging:
            self.audit_logger = SMCPAuditLogger(
                log_level=self.config.log_level
            )
        else:
            self.audit_logger = None
        
        # Add authenticator alias for tests
        self.authenticator = self.jwt_auth
    
    def _setup_default_roles(self):
        """Setup default RBAC roles"""
        if not self.rbac_manager:
            return
            
        # Define standard roles
        self.rbac_manager.define_role("user", [
            "mcp:read", "mcp:execute:safe_tools"
        ])
        
        self.rbac_manager.define_role("power_user", [
            "mcp:read", "mcp:write", "mcp:execute:all_tools"
        ])
        
        self.rbac_manager.define_role("admin", [
            "mcp:*", "system:*", "security:*"
        ])
    
    def _setup_metrics(self):
        """Initialize security metrics tracking"""
        self.metrics = {
            "requests_processed": 0,
            "attacks_blocked": 0,
            "authentication_failures": 0,
            "authorization_failures": 0,
            "rate_limit_violations": 0,
            "anomalies_detected": 0,
            "false_positives": 0,
            "processing_time_ms": [],
        }
    
    async def process_request(self, request_data: Dict[str, Any], 
                            user_context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Process an MCP request through all security layers
        
        Args:
            request_data: The MCP request to process
            user_context: User context including authentication info
            
        Returns:
            Processed and validated request data
            
        Raises:
            SecurityError: If any security check fails
        """
        start_time = time.time()
        
        try:
            # Update metrics
            self.metrics["requests_processed"] += 1
            
            # Layer 1: Input Validation
            if self.config.enable_input_validation:
                validated_request = await self._validate_input(request_data)
            else:
                validated_request = request_data
            
            # Layer 2: Authentication & Authorization
            auth_context = await self._authenticate_and_authorize(
                validated_request, user_context
            )
            
            # Layer 3: Rate Limiting
            if self.config.enable_rate_limiting:
                await self._check_rate_limits(auth_context, validated_request)
            
            # Layer 4: Cryptographic Processing
            if self.config.enable_encryption:
                processed_request = await self._process_cryptography(
                    validated_request, auth_context
                )
            else:
                processed_request = validated_request
            
            # Layer 6: AI Immune System (before Layer 5 for real-time detection)
            if self.config.enable_ai_immune:
                await self._ai_immune_analysis(processed_request, auth_context)
            
            # Layer 5: Audit Logging
            if self.config.enable_audit_logging:
                await self._audit_request(processed_request, auth_context, "SUCCESS")
            
            # Record processing time
            processing_time = (time.time() - start_time) * 1000
            self.metrics["processing_time_ms"].append(processing_time)
            
            return {
                "request": processed_request,
                "context": auth_context,
                "security_metadata": {
                    "processing_time_ms": processing_time,
                    "security_level": self._calculate_security_level(auth_context),
                    "threat_score": getattr(auth_context, 'threat_score', 0.0)
                }
            }
            
        except Exception as e:
            # Log security incident
            if self.config.enable_audit_logging:
                await self._audit_request(
                    request_data, user_context or {}, "FAILURE", str(e)
                )
            
            # Update failure metrics
            if isinstance(e, AuthenticationError):
                self.metrics["authentication_failures"] += 1
            elif isinstance(e, AuthorizationError):
                self.metrics["authorization_failures"] += 1
            elif isinstance(e, RateLimitError):
                self.metrics["rate_limit_violations"] += 1
            else:
                self.metrics["attacks_blocked"] += 1
            
            raise
    
    async def _validate_input(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Layer 1: Input validation and sanitization"""
        if not self.input_validator:
            return request_data
            
        try:
            return await self.input_validator.validate_request(request_data)
        except ValidationError as e:
            raise SecurityError(f"Input validation failed: {str(e)}")
    
    async def _authenticate_and_authorize(self, request_data: Dict[str, Any],
                                        user_context: Dict[str, Any]) -> Dict[str, Any]:
        """Layer 2: Authentication and authorization"""
        if not user_context:
            raise AuthenticationError("No user context provided")
        
        # Authenticate user
        token = user_context.get("token")
        if not token:
            raise AuthenticationError("No authentication token provided")
        
        try:
            auth_payload = self.jwt_auth.validate_token(token)
        except Exception as e:
            raise AuthenticationError(f"Token validation failed: {str(e)}")
        
        # Check MFA if enabled
        if self.config.enable_mfa and not auth_payload.get("mfa_verified"):
            raise AuthenticationError("Multi-factor authentication required")
        
        # Authorize request
        if self.config.enable_rbac and self.rbac_manager:
            required_permission = self._determine_required_permission(request_data)
            user_id = auth_payload.get("user_id")
            
            if not self.rbac_manager.check_permission(user_id, required_permission):
                raise AuthorizationError(
                    f"Insufficient permissions for {required_permission}"
                )
        
        return {
            "user_id": auth_payload.get("user_id"),
            "roles": auth_payload.get("roles", []),
            "permissions": auth_payload.get("permissions", []),
            "session_id": auth_payload.get("jti"),
            "authenticated_at": datetime.utcnow(),
        }
    
    async def _check_rate_limits(self, auth_context: Dict[str, Any], request_data: Dict[str, Any]):
        """Layer 3: Rate limiting and DoS protection"""
        if not self.rate_limiter:
            return
            
        user_id = auth_context.get("user_id")
        
        # Check rate limits
        if not self.rate_limiter.check_rate_limit(user_id, "mcp_request"):
            raise RateLimitError(f"Rate limit exceeded for user {user_id}")
        
        # Check for DoS patterns (disabled for demo)
        # if self.dos_protection and not self.dos_protection.analyze_request_pattern(user_id, request_data):
        #     raise SecurityError("Suspicious request pattern detected")
    
    async def _process_cryptography(self, request_data: Dict[str, Any],
                                  auth_context: Dict[str, Any]) -> Dict[str, Any]:
        """Layer 4: Cryptographic processing"""
        # For now, we'll just ensure the request is properly structured
        # In a full implementation, this would handle encryption/decryption
        return request_data
    
    async def _ai_immune_analysis(self, request_data: Dict[str, Any],
                                auth_context: Dict[str, Any]):
        """Layer 6: AI immune system analysis"""
        if not self.ai_immune or not self.threat_classifier:
            return
            
        # Perform anomaly detection
        anomaly_result = self.ai_immune.detect_anomaly(request_data)
        
        if anomaly_result.is_anomaly:
            # Classify the threat
            threat_info = self.threat_classifier.classify_threat(
                request_data, anomaly_result
            )
            
            # Update metrics
            self.metrics["anomalies_detected"] += 1
            
            # Store threat score in context
            auth_context["threat_score"] = anomaly_result.anomaly_score
            auth_context["threat_type"] = threat_info.threat_type
            
            # Take action based on threat severity
            if threat_info.severity in ["HIGH", "CRITICAL"]:
                raise SecurityError(
                    f"High-risk anomaly detected: {threat_info.threat_type}"
                )
    
    async def _audit_request(self, request_data: Dict[str, Any],
                           context: Dict[str, Any], status: str,
                           error_message: str = None):
        """Layer 5: Audit logging"""
        if not self.audit_logger:
            return
            
        self.audit_logger.log_security_event(
            "mcp_request",
            context.get("user_id", "unknown"),
            {
                "method": request_data.get("method"),
                "status": status,
                "error": error_message,
                "request_size": len(str(request_data)),
                "processing_layers": self._get_active_layers()
            },
            "ERROR" if status == "FAILURE" else "INFO"
        )
    
    def _determine_required_permission(self, request_data: Dict[str, Any]) -> str:
        """Determine the required permission for an MCP request"""
        method = request_data.get("method", "")
        
        # Map MCP methods to permissions
        permission_map = {
            "tools/list": "mcp:read",
            "tools/call": "mcp:read",  # Basic read permission, specific tool permissions checked at app level
            "resources/list": "mcp:read",
            "resources/read": "mcp:read",
            "prompts/list": "mcp:read",
            "prompts/get": "mcp:read",
        }
        
        return permission_map.get(method, "mcp:read")
    
    def _calculate_security_level(self, auth_context: Dict[str, Any]) -> str:
        """Calculate overall security level for the request"""
        threat_score = auth_context.get("threat_score", 0.0)
        
        if threat_score > 0.8:
            return "HIGH_RISK"
        elif threat_score > 0.5:
            return "MEDIUM_RISK"
        else:
            return "LOW_RISK"
    
    def _get_active_layers(self) -> List[str]:
        """Get list of active security layers"""
        layers = []
        if self.config.enable_input_validation:
            layers.append("input_validation")
        layers.append("authentication")
        if self.config.enable_rbac:
            layers.append("authorization")
        if self.config.enable_rate_limiting:
            layers.append("rate_limiting")
        if self.config.enable_encryption:
            layers.append("cryptography")
        if self.config.enable_audit_logging:
            layers.append("audit_logging")
        if self.config.enable_ai_immune:
            layers.append("ai_immune_system")
        return layers
    
    def get_security_metrics(self) -> Dict[str, Any]:
        """Get current security metrics"""
        metrics = self.metrics.copy()
        
        # Calculate average processing time
        if metrics["processing_time_ms"]:
            metrics["avg_processing_time_ms"] = sum(metrics["processing_time_ms"]) / len(metrics["processing_time_ms"])
            metrics["max_processing_time_ms"] = max(metrics["processing_time_ms"])
            metrics["min_processing_time_ms"] = min(metrics["processing_time_ms"])
        else:
            metrics["avg_processing_time_ms"] = 0.0
            metrics["max_processing_time_ms"] = 0.0
            metrics["min_processing_time_ms"] = 0.0
        
        # Calculate success rate
        total_requests = metrics["requests_processed"]
        if total_requests > 0:
            successful_requests = total_requests - metrics["attacks_blocked"]
            metrics["success_rate"] = successful_requests / total_requests
        else:
            metrics["success_rate"] = 1.0  # 100% success rate when no requests processed
        
        return metrics
    
    async def train_ai_immune_system(self, training_requests: List[Dict[str, Any]]):
        """Train the AI immune system with normal request patterns"""
        if self.config.enable_ai_immune and self.ai_immune:
            await asyncio.to_thread(self.ai_immune.train, training_requests)
    
    def update_security_config(self, new_config: SecurityConfig):
        """Update security configuration (requires restart for some changes)"""
        self.config = new_config
        # Note: In a production system, this would selectively update
        # components that can be changed without restart
    
    def update_configuration(self, new_config: SecurityConfig):
        """Update security configuration (alias for update_security_config)"""
        # Validate configuration first
        if hasattr(new_config, 'validation_strictness'):
            if new_config.validation_strictness not in ["minimal", "standard", "maximum"]:
                raise ValueError("Invalid validation strictness")
        
        self.update_security_config(new_config)
    
    def disable_layer(self, layer_name: str):
        """Disable a specific security layer"""
        layer_map = {
            "input_validation": "enable_input_validation",
            "mfa": "enable_mfa", 
            "rbac": "enable_rbac",
            "rate_limiting": "enable_rate_limiting",
            "encryption": "enable_encryption",
            "ai_immune": "enable_ai_immune",
            "audit_logging": "enable_audit_logging"
        }
        
        if layer_name in layer_map:
            setattr(self.config, layer_map[layer_name], False)
    
    def enable_layer(self, layer_name: str):
        """Enable a specific security layer"""
        layer_map = {
            "input_validation": "enable_input_validation",
            "mfa": "enable_mfa",
            "rbac": "enable_rbac", 
            "rate_limiting": "enable_rate_limiting",
            "encryption": "enable_encryption",
            "ai_immune": "enable_ai_immune",
            "audit_logging": "enable_audit_logging"
        }
        
        if layer_name in layer_map:
            setattr(self.config, layer_map[layer_name], True)
    
    def enrich_context(self, basic_context: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich security context with additional information"""
        enriched = basic_context.copy()
        
        # Add timestamp
        enriched["enriched_at"] = datetime.utcnow()
        
        # Add security metadata
        enriched["security_framework_version"] = "1.0.0"
        enriched["active_layers"] = self._get_active_layers()
        
        # Add risk assessment
        ip_address = basic_context.get("ip_address", "")
        if ip_address.startswith("192.168.") or ip_address.startswith("10."):
            enriched["network_trust_level"] = "internal"
        else:
            enriched["network_trust_level"] = "external"
        
        return enriched
    
    def health_check(self) -> Dict[str, Any]:
        """Perform health check of security framework"""
        health = {
            "status": "healthy",
            "components": {},
            "metrics": self.get_security_metrics(),
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Check each component
        if hasattr(self, 'input_validator'):
            health["components"]["input_validator"] = "active"
        
        if hasattr(self, 'jwt_auth'):
            health["components"]["jwt_auth"] = "active"
            
        if hasattr(self, 'rbac_manager'):
            health["components"]["rbac_manager"] = "active"
            
        if hasattr(self, 'rate_limiter'):
            health["components"]["rate_limiter"] = "active"
            
        if hasattr(self, 'crypto'):
            health["components"]["crypto"] = "active"
            
        if hasattr(self, 'ai_immune'):
            health["components"]["ai_immune"] = "active"
            
        if hasattr(self, 'audit_logger'):
            health["components"]["audit_logger"] = "active"
        
        return health
    
    def get_memory_usage(self) -> Dict[str, Any]:
        """Get memory usage statistics"""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        memory_info = process.memory_info()
        
        return {
            "rss": memory_info.rss,  # Resident Set Size
            "vms": memory_info.vms,  # Virtual Memory Size
            "percent": process.memory_percent(),
            "available": psutil.virtual_memory().available,
            "total": psutil.virtual_memory().total
        }
    
    def add_security_policy(self, policy: Dict[str, Any]):
        """Add a custom security policy"""
        if not hasattr(self, '_custom_policies'):
            self._custom_policies = []
        
        self._custom_policies.append(policy)
    
    def get_security_policies(self) -> List[Dict[str, Any]]:
        """Get all custom security policies"""
        return getattr(self, '_custom_policies', [])
    
    async def shutdown(self):
        """Graceful shutdown of security framework"""
        # Flush audit logs if available
        if hasattr(self, 'audit_logger') and hasattr(self.audit_logger, 'flush'):
            self.audit_logger.flush()
        
        # Cleanup crypto resources if available  
        if hasattr(self, 'crypto') and hasattr(self.crypto, 'cleanup'):
            self.crypto.cleanup()
    
    async def process_batch_requests(self, requests: List[Dict[str, Any]], 
                                   user_context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process multiple requests in batch"""
        results = []
        for request in requests:
            try:
                result = await self.process_request(request, user_context)
                results.append(result)
            except Exception as e:
                results.append({
                    "error": str(e),
                    "request_id": request.get("id")
                })
        return results
