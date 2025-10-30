"""Unit tests for core SMCP security framework.

Tests the SMCPSecurityFramework integration and core functionality.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime

from smcp_security.core import SMCPSecurityFramework, SecurityConfig
from smcp_security.exceptions import SecurityError, ValidationError, AuthenticationError


class TestSecurityConfig:
    """Test security configuration."""
    
    @pytest.mark.unit
    def test_default_config_creation(self):
        """Test creation of default security config."""
        config = SecurityConfig()
        
        assert config.enable_input_validation is True
        assert config.validation_strictness == "standard"
        assert config.enable_mfa is True
        assert config.jwt_expiry_seconds == 3600
        assert config.enable_rbac is True
        assert config.enable_rate_limiting is True
        assert config.default_rate_limit == 100
        assert config.enable_encryption is True
        assert config.enable_ai_immune is True
        assert config.anomaly_threshold == 0.7
        assert config.enable_audit_logging is True
        assert config.log_level == "INFO"
    
    @pytest.mark.unit
    def test_custom_config_creation(self):
        """Test creation of custom security config."""
        config = SecurityConfig(
            enable_input_validation=False,
            validation_strictness="minimal",
            enable_mfa=False,
            jwt_expiry_seconds=7200,
            enable_rbac=False,
            enable_rate_limiting=False,
            enable_encryption=False,
            enable_ai_immune=False,
            enable_audit_logging=False,
            log_level="DEBUG"
        )
        
        assert config.enable_input_validation is False
        assert config.validation_strictness == "minimal"
        assert config.enable_mfa is False
        assert config.jwt_expiry_seconds == 7200
        assert config.enable_rbac is False
        assert config.enable_rate_limiting is False
        assert config.enable_encryption is False
        assert config.enable_ai_immune is False
        assert config.enable_audit_logging is False
        assert config.log_level == "DEBUG"
    
    @pytest.mark.unit
    def test_config_validation(self):
        """Test configuration validation."""
        # Test invalid strictness level
        with pytest.raises(ValueError, match="Invalid validation strictness"):
            SecurityConfig(validation_strictness="invalid")
        
        # Test invalid log level
        with pytest.raises(ValueError, match="Invalid log level"):
            SecurityConfig(log_level="INVALID")
        
        # Test invalid rate limit
        with pytest.raises(ValueError, match="Rate limit must be positive"):
            SecurityConfig(default_rate_limit=0)
        
        # Test invalid JWT expiry
        with pytest.raises(ValueError, match="JWT expiry must be positive"):
            SecurityConfig(jwt_expiry_seconds=0)


class TestSMCPSecurityFramework:
    """Test SMCP security framework integration."""
    
    @pytest.fixture
    def security_config(self):
        return SecurityConfig(
            enable_mfa=False,  # Disable for testing
            log_level="DEBUG"
        )
    
    @pytest.fixture
    def security_framework(self, security_config):
        return SMCPSecurityFramework(security_config)
    
    @pytest.fixture
    def minimal_framework(self):
        config = SecurityConfig(
            enable_input_validation=True,
            enable_mfa=False,
            enable_rbac=False,
            enable_rate_limiting=False,
            enable_encryption=False,
            enable_ai_immune=False,
            enable_audit_logging=False
        )
        return SMCPSecurityFramework(config)
    
    @pytest.mark.unit
    def test_framework_initialization(self, security_framework):
        """Test security framework initialization."""
        assert security_framework.config is not None
        assert security_framework.input_validator is not None
        assert security_framework.authenticator is not None
        assert security_framework.rbac_manager is not None
        assert security_framework.rate_limiter is not None
        assert security_framework.crypto_manager is not None
        assert security_framework.audit_logger is not None
        assert security_framework.ai_immune_system is not None
    
    @pytest.mark.unit
    def test_minimal_framework_initialization(self, minimal_framework):
        """Test minimal framework initialization with disabled components."""
        assert minimal_framework.config is not None
        assert minimal_framework.input_validator is not None
        # Other components should be None when disabled
        assert minimal_framework.rbac_manager is None
        assert minimal_framework.rate_limiter is None
        assert minimal_framework.crypto_manager is None
        assert minimal_framework.audit_logger is None
        assert minimal_framework.ai_immune_system is None
    
    @pytest.mark.unit
    async def test_process_request_valid(self, security_framework, valid_mcp_request, user_context):
        """Test processing valid MCP request."""
        result = await security_framework.process_request(valid_mcp_request, user_context)
        
        assert "request" in result
        assert "context" in result
        assert "security_metadata" in result
        
        # Request should be processed successfully
        assert result["request"] is not None
        assert result["context"]["user_id"] == user_context["user_id"]
        
        # Security metadata should be present
        metadata = result["security_metadata"]
        assert "processing_time_ms" in metadata
        assert "security_level" in metadata
        assert "layers_processed" in metadata
    
    @pytest.mark.unit
    async def test_process_request_invalid_schema(self, security_framework, user_context):
        """Test processing request with invalid schema."""
        invalid_request = {
            "jsonrpc": "1.0",  # Invalid version
            "method": "test"
        }
        
        with pytest.raises(ValidationError, match="Schema validation failed"):
            await security_framework.process_request(invalid_request, user_context)
    
    @pytest.mark.unit
    async def test_process_request_malicious(self, security_framework, user_context):
        """Test processing malicious request."""
        malicious_request = {
            "jsonrpc": "2.0",
            "id": "malicious",
            "method": "tools/call",
            "params": {
                "command": "ls; rm -rf /"  # Command injection
            }
        }
        
        with pytest.raises(SecurityError, match="Dangerous pattern detected"):
            await security_framework.process_request(malicious_request, user_context)
    
    @pytest.mark.unit
    async def test_process_request_unauthenticated(self, security_framework):
        """Test processing request without authentication."""
        request = {
            "jsonrpc": "2.0",
            "id": "test",
            "method": "tools/list",
            "params": {}
        }
        
        invalid_context = {
            "user_id": "test_user",
            "token": "invalid-token",
            "ip_address": "192.168.1.100"
        }
        
        with pytest.raises(AuthenticationError):
            await security_framework.process_request(request, invalid_context)
    
    @pytest.mark.unit
    async def test_process_request_rate_limited(self, security_framework, user_context):
        """Test processing request when rate limited."""
        request = {
            "jsonrpc": "2.0",
            "id": "test",
            "method": "tools/list",
            "params": {}
        }
        
        # Simulate rate limit exceeded
        with patch.object(security_framework.rate_limiter, 'check_rate_limit') as mock_rate_limit:
            from smcp_security.exceptions import RateLimitError
            mock_rate_limit.side_effect = RateLimitError("Rate limit exceeded")
            
            with pytest.raises(RateLimitError):
                await security_framework.process_request(request, user_context)
    
    @pytest.mark.unit
    async def test_security_layer_processing_order(self, security_framework, valid_mcp_request, user_context):
        """Test that security layers are processed in correct order."""
        processing_order = []
        
        # Mock each layer to track processing order
        with patch.object(security_framework.input_validator, 'validate_request') as mock_input, \
             patch.object(security_framework.authenticator, 'validate_token') as mock_auth, \
             patch.object(security_framework.rbac_manager, 'check_permission') as mock_rbac, \
             patch.object(security_framework.rate_limiter, 'check_rate_limit') as mock_rate, \
             patch.object(security_framework.ai_immune_system, 'analyze_request') as mock_ai:
            
            # Configure mocks to track order
            mock_input.side_effect = lambda x: (processing_order.append('input'), x)[1]
            mock_auth.return_value = {"user_id": "test_user", "roles": ["user"]}
            mock_auth.side_effect = lambda x: (processing_order.append('auth'), mock_auth.return_value)[1]
            mock_rbac.return_value = True
            mock_rbac.side_effect = lambda *args: (processing_order.append('rbac'), True)[1]
            mock_rate.return_value = True
            mock_rate.side_effect = lambda x: (processing_order.append('rate'), True)[1]
            mock_ai.return_value = {"overall_risk_score": 0.1, "recommendation": "allow"}
            mock_ai.side_effect = lambda *args: (processing_order.append('ai'), mock_ai.return_value)[1]
            
            await security_framework.process_request(valid_mcp_request, user_context)
            
            # Verify processing order
            expected_order = ['input', 'auth', 'rbac', 'rate', 'ai']
            assert processing_order == expected_order
    
    @pytest.mark.unit
    async def test_security_metadata_generation(self, security_framework, valid_mcp_request, user_context):
        """Test security metadata generation."""
        result = await security_framework.process_request(valid_mcp_request, user_context)
        
        metadata = result["security_metadata"]
        
        # Check required metadata fields
        assert "processing_time_ms" in metadata
        assert "security_level" in metadata
        assert "threat_score" in metadata
        assert "layers_processed" in metadata
        assert "timestamp" in metadata
        
        # Check metadata types and ranges
        assert isinstance(metadata["processing_time_ms"], (int, float))
        assert metadata["processing_time_ms"] >= 0
        assert metadata["security_level"] in ["LOW_RISK", "MEDIUM_RISK", "HIGH_RISK", "CRITICAL_RISK"]
        assert 0.0 <= metadata["threat_score"] <= 1.0
        assert isinstance(metadata["layers_processed"], list)
        assert len(metadata["layers_processed"]) > 0
    
    @pytest.mark.unit
    def test_get_security_metrics(self, security_framework):
        """Test getting security metrics."""
        metrics = security_framework.get_security_metrics()
        
        assert "requests_processed" in metrics
        assert "attacks_blocked" in metrics
        assert "success_rate" in metrics
        assert "avg_processing_time_ms" in metrics
        assert "layer_performance" in metrics
        
        # Check metric types
        assert isinstance(metrics["requests_processed"], int)
        assert isinstance(metrics["attacks_blocked"], int)
        assert isinstance(metrics["success_rate"], float)
        assert isinstance(metrics["avg_processing_time_ms"], float)
        assert isinstance(metrics["layer_performance"], dict)
    
    @pytest.mark.unit
    def test_update_configuration(self, security_framework):
        """Test updating security configuration."""
        new_config = SecurityConfig(
            enable_input_validation=True,
            validation_strictness="maximum",
            enable_mfa=True,
            default_rate_limit=50
        )
        
        security_framework.update_configuration(new_config)
        
        assert security_framework.config.validation_strictness == "maximum"
        assert security_framework.config.enable_mfa is True
        assert security_framework.config.default_rate_limit == 50
    
    @pytest.mark.unit
    def test_enable_disable_layers(self, security_framework):
        """Test enabling and disabling security layers."""
        # Disable AI immune system
        security_framework.disable_layer("ai_immune")
        assert security_framework.ai_immune_system is None
        
        # Re-enable AI immune system
        security_framework.enable_layer("ai_immune")
        assert security_framework.ai_immune_system is not None
        
        # Test invalid layer name
        with pytest.raises(ValueError, match="Unknown security layer"):
            security_framework.disable_layer("invalid_layer")
    
    @pytest.mark.unit
    async def test_batch_request_processing(self, security_framework, user_context):
        """Test processing multiple requests in batch."""
        requests = [
            {
                "jsonrpc": "2.0",
                "id": f"batch_{i}",
                "method": "tools/list",
                "params": {}
            }
            for i in range(5)
        ]
        
        results = await security_framework.process_batch_requests(requests, user_context)
        
        assert len(results) == 5
        
        for i, result in enumerate(results):
            assert "request" in result
            assert "context" in result
            assert "security_metadata" in result
            assert result["request"]["id"] == f"batch_{i}"
    
    @pytest.mark.unit
    async def test_error_handling_and_recovery(self, security_framework, user_context):
        """Test error handling and recovery mechanisms."""
        request = {
            "jsonrpc": "2.0",
            "id": "error_test",
            "method": "tools/list",
            "params": {}
        }
        
        # Simulate error in one layer
        with patch.object(security_framework.ai_immune_system, 'analyze_request') as mock_ai:
            mock_ai.side_effect = Exception("AI system error")
            
            # Should still process request with degraded security
            result = await security_framework.process_request(request, user_context)
            
            assert "request" in result
            assert "security_metadata" in result
            
            # Should indicate degraded security
            metadata = result["security_metadata"]
            assert "errors" in metadata
            assert "ai_immune" in metadata["errors"]
    
    @pytest.mark.unit
    def test_security_event_logging(self, security_framework):
        """Test security event logging."""
        # Mock audit logger
        with patch.object(security_framework.audit_logger, 'log_security_violation') as mock_log:
            security_framework.log_security_event(
                event_type="test_violation",
                user_id="test_user",
                details="Test security event",
                severity="HIGH"
            )
            
            mock_log.assert_called_once()
            call_args = mock_log.call_args[1]
            assert call_args["user_id"] == "test_user"
            assert call_args["violation_type"] == "test_violation"
            assert call_args["details"] == "Test security event"
    
    @pytest.mark.unit
    def test_context_enrichment(self, security_framework):
        """Test security context enrichment."""
        basic_context = {
            "user_id": "test_user",
            "ip_address": "192.168.1.100"
        }
        
        enriched_context = security_framework.enrich_context(basic_context)
        
        # Should add additional context information
        assert "timestamp" in enriched_context
        assert "session_id" in enriched_context
        assert "request_id" in enriched_context
        assert "geolocation" in enriched_context
        
        # Original context should be preserved
        assert enriched_context["user_id"] == "test_user"
        assert enriched_context["ip_address"] == "192.168.1.100"
    
    @pytest.mark.unit
    async def test_async_processing_performance(self, security_framework, user_context, benchmark):
        """Test asynchronous processing performance."""
        request = {
            "jsonrpc": "2.0",
            "id": "perf_test",
            "method": "tools/list",
            "params": {}
        }
        
        async def process_request():
            return await security_framework.process_request(request, user_context)
        
        # Benchmark async processing
        result = await process_request()
        
        assert "request" in result
        assert "security_metadata" in result
        
        # Processing time should be reasonable
        processing_time = result["security_metadata"]["processing_time_ms"]
        assert processing_time < 1000  # Less than 1 second
    
    @pytest.mark.unit
    def test_health_check(self, security_framework):
        """Test security framework health check."""
        health = security_framework.health_check()
        
        assert "status" in health
        assert "components" in health
        assert "uptime_seconds" in health
        assert "last_check" in health
        
        # Check component health
        components = health["components"]
        expected_components = [
            "input_validator", "authenticator", "rbac_manager",
            "rate_limiter", "crypto_manager", "audit_logger", "ai_immune_system"
        ]
        
        for component in expected_components:
            if getattr(security_framework, component) is not None:
                assert component in components
                assert "status" in components[component]
    
    @pytest.mark.unit
    def test_graceful_shutdown(self, security_framework):
        """Test graceful shutdown of security framework."""
        # Mock component shutdown methods
        with patch.object(security_framework.audit_logger, 'flush') as mock_flush, \
             patch.object(security_framework.crypto_manager, 'cleanup') as mock_cleanup:
            
            security_framework.shutdown()
            
            # Should flush logs and cleanup resources
            mock_flush.assert_called_once()
            mock_cleanup.assert_called_once()
    
    @pytest.mark.unit
    def test_configuration_validation_on_update(self, security_framework):
        """Test configuration validation when updating."""
        # Test invalid configuration
        invalid_config = SecurityConfig(validation_strictness="invalid")
        
        with pytest.raises(ValueError):
            security_framework.update_configuration(invalid_config)
        
        # Original configuration should remain unchanged
        assert security_framework.config.validation_strictness == "standard"
    
    @pytest.mark.unit
    async def test_concurrent_request_processing(self, security_framework, user_context):
        """Test concurrent request processing."""
        import asyncio
        
        requests = [
            {
                "jsonrpc": "2.0",
                "id": f"concurrent_{i}",
                "method": "tools/list",
                "params": {}
            }
            for i in range(10)
        ]
        
        # Process requests concurrently
        tasks = [
            security_framework.process_request(request, user_context)
            for request in requests
        ]
        
        results = await asyncio.gather(*tasks)
        
        assert len(results) == 10
        
        # All requests should be processed successfully
        for i, result in enumerate(results):
            assert result["request"]["id"] == f"concurrent_{i}"
            assert "security_metadata" in result
    
    @pytest.mark.unit
    def test_memory_usage_monitoring(self, security_framework):
        """Test memory usage monitoring."""
        memory_stats = security_framework.get_memory_usage()
        
        assert "total_memory_mb" in memory_stats
        assert "used_memory_mb" in memory_stats
        assert "memory_percentage" in memory_stats
        assert "component_memory" in memory_stats
        
        # Memory values should be reasonable
        assert memory_stats["total_memory_mb"] > 0
        assert memory_stats["used_memory_mb"] > 0
        assert 0 <= memory_stats["memory_percentage"] <= 100
    
    @pytest.mark.unit
    def test_custom_security_policies(self, security_framework):
        """Test custom security policy application."""
        custom_policy = {
            "name": "test_policy",
            "rules": [
                {
                    "condition": "method == 'tools/call'",
                    "action": "require_mfa"
                },
                {
                    "condition": "ip_address.startswith('10.')",
                    "action": "block"
                }
            ]
        }
        
        security_framework.add_security_policy(custom_policy)
        
        policies = security_framework.get_security_policies()
        assert "test_policy" in [p["name"] for p in policies]
    
    @pytest.mark.unit
    async def test_security_policy_enforcement(self, security_framework, user_context):
        """Test security policy enforcement."""
        # Add policy to block internal IPs
        policy = {
            "name": "block_internal",
            "rules": [
                {
                    "condition": "ip_address.startswith('10.')",
                    "action": "block"
                }
            ]
        }
        
        security_framework.add_security_policy(policy)
        
        # Test with internal IP
        internal_context = user_context.copy()
        internal_context["ip_address"] = "10.0.0.1"
        
        request = {
            "jsonrpc": "2.0",
            "id": "policy_test",
            "method": "tools/list",
            "params": {}
        }
        
        with pytest.raises(SecurityError, match="Blocked by security policy"):
            await security_framework.process_request(request, internal_context)
