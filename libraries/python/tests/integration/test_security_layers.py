"""Integration tests for security layer interactions.

Tests the integration and interaction between different security layers
to ensure they work together correctly.
"""

import pytest
import asyncio
from unittest.mock import patch

from smcp_security.core import SMCPSecurityFramework, SecurityConfig
from smcp_security.exceptions import SecurityError, ValidationError, AuthenticationError, RateLimitError


class TestSecurityLayerIntegration:
    """Test integration between security layers."""
    
    @pytest.fixture
    def full_security_framework(self):
        """Framework with all security layers enabled."""
        config = SecurityConfig(
            enable_input_validation=True,
            validation_strictness="standard",
            enable_mfa=False,  # Disabled for testing
            enable_rbac=True,
            enable_rate_limiting=True,
            default_rate_limit=10,
            enable_encryption=True,
            enable_ai_immune=True,
            anomaly_threshold=0.8,
            enable_audit_logging=True,
            log_level="DEBUG"
        )
        return SMCPSecurityFramework(config)
    
    @pytest.fixture
    def authenticated_context(self, full_security_framework):
        """Create authenticated user context."""
        # Generate valid JWT token
        token = full_security_framework.authenticator.generate_token(
            user_id="test_user",
            roles=["user"],
            permissions=["mcp:read", "mcp:execute:safe_tools"]
        )
        
        return {
            "user_id": "test_user",
            "token": token,
            "ip_address": "192.168.1.100",
            "user_agent": "SMCP-Client/1.0"
        }
    
    @pytest.mark.integration
    @pytest.mark.security
    async def test_input_validation_to_authentication_flow(self, full_security_framework, authenticated_context):
        """Test flow from input validation to authentication."""
        # Valid request that passes input validation
        request = {
            "jsonrpc": "2.0",
            "id": "test_request",
            "method": "tools/list",
            "params": {}
        }
        
        result = await full_security_framework.process_request(request, authenticated_context)
        
        # Should pass both input validation and authentication
        assert "request" in result
        assert "security_metadata" in result
        
        layers_processed = result["security_metadata"]["layers_processed"]
        assert "input_validation" in layers_processed
        assert "authentication" in layers_processed
    
    @pytest.mark.integration
    @pytest.mark.security
    async def test_malicious_request_blocked_early(self, full_security_framework, authenticated_context):
        """Test that malicious requests are blocked at input validation."""
        # Malicious request with command injection
        malicious_request = {
            "jsonrpc": "2.0",
            "id": "malicious",
            "method": "tools/call",
            "params": {
                "command": "ls; rm -rf /"
            }
        }
        
        # Should be blocked at input validation layer
        with pytest.raises(SecurityError, match="Dangerous pattern detected"):
            await full_security_framework.process_request(malicious_request, authenticated_context)
    
    @pytest.mark.integration
    @pytest.mark.security
    async def test_authentication_to_authorization_flow(self, full_security_framework):
        """Test flow from authentication to authorization."""
        # Create user with limited permissions
        limited_token = full_security_framework.authenticator.generate_token(
            user_id="limited_user",
            roles=["guest"],
            permissions=["mcp:read"]
        )
        
        limited_context = {
            "user_id": "limited_user",
            "token": limited_token,
            "ip_address": "192.168.1.101"
        }
        
        # Request that requires write permission
        write_request = {
            "jsonrpc": "2.0",
            "id": "write_test",
            "method": "tools/call",
            "params": {
                "name": "file_writer",
                "args": {"content": "test"}
            }
        }
        
        # Should pass authentication but fail authorization
        with pytest.raises(SecurityError, match="Insufficient permissions"):
            await full_security_framework.process_request(write_request, limited_context)
    
    @pytest.mark.integration
    @pytest.mark.security
    async def test_rate_limiting_integration(self, full_security_framework, authenticated_context):
        """Test rate limiting integration with other layers."""
        request = {
            "jsonrpc": "2.0",
            "id": "rate_test",
            "method": "tools/list",
            "params": {}
        }
        
        # Make requests up to the limit
        for i in range(10):
            result = await full_security_framework.process_request(request, authenticated_context)
            assert "request" in result
        
        # Next request should be rate limited
        with pytest.raises(RateLimitError):
            await full_security_framework.process_request(request, authenticated_context)
    
    @pytest.mark.integration
    @pytest.mark.security
    async def test_ai_immune_system_integration(self, full_security_framework, authenticated_context):
        """Test AI immune system integration with other layers."""
        # Request that might be flagged by AI system
        suspicious_request = {
            "jsonrpc": "2.0",
            "id": "suspicious",
            "method": "tools/call",
            "params": {
                "command": "unusual_pattern_" + "x" * 1000,
                "data": "suspicious_data_pattern"
            }
        }
        
        # Should pass other layers but be analyzed by AI system
        result = await full_security_framework.process_request(suspicious_request, authenticated_context)
        
        # Check AI analysis in metadata
        metadata = result["security_metadata"]
        assert "ai_analysis" in metadata
        assert "threat_score" in metadata
    
    @pytest.mark.integration
    @pytest.mark.security
    async def test_encryption_integration(self, full_security_framework, authenticated_context):
        """Test encryption integration with request processing."""
        request = {
            "jsonrpc": "2.0",
            "id": "encryption_test",
            "method": "tools/call",
            "params": {
                "sensitive_data": "confidential information"
            }
        }
        
        result = await full_security_framework.process_request(request, authenticated_context)
        
        # Check that encryption metadata is present
        metadata = result["security_metadata"]
        assert "encryption_applied" in metadata
        
        # Sensitive data should be encrypted in the processed request
        processed_request = result["request"]
        if "encrypted_params" in processed_request:
            assert processed_request["encrypted_params"] != request["params"]
    
    @pytest.mark.integration
    @pytest.mark.security
    async def test_audit_logging_integration(self, full_security_framework, authenticated_context):
        """Test audit logging integration across all layers."""
        request = {
            "jsonrpc": "2.0",
            "id": "audit_test",
            "method": "tools/call",
            "params": {
                "name": "test_tool"
            }
        }
        
        # Process request
        result = await full_security_framework.process_request(request, authenticated_context)
        
        # Check that events were logged
        audit_events = full_security_framework.audit_logger.get_events(limit=10)
        
        # Should have events from multiple layers
        event_categories = [event["category"] for event in audit_events]
        assert "INPUT_VALIDATION" in event_categories
        assert "AUTHENTICATION" in event_categories
        assert "AUTHORIZATION" in event_categories
    
    @pytest.mark.integration
    @pytest.mark.security
    async def test_layer_failure_isolation(self, full_security_framework, authenticated_context):
        """Test that failure in one layer doesn't break others."""
        request = {
            "jsonrpc": "2.0",
            "id": "failure_test",
            "method": "tools/list",
            "params": {}
        }
        
        # Simulate failure in AI immune system
        with patch.object(full_security_framework.ai_immune_system, 'analyze_request') as mock_ai:
            mock_ai.side_effect = Exception("AI system failure")
            
            # Should still process request with other layers
            result = await full_security_framework.process_request(request, authenticated_context)
            
            assert "request" in result
            assert "security_metadata" in result
            
            # Should indicate degraded security
            metadata = result["security_metadata"]
            assert "errors" in metadata
            assert "ai_immune" in metadata["errors"]
    
    @pytest.mark.integration
    @pytest.mark.security
    async def test_security_context_propagation(self, full_security_framework, authenticated_context):
        """Test that security context is properly propagated between layers."""
        request = {
            "jsonrpc": "2.0",
            "id": "context_test",
            "method": "tools/call",
            "params": {
                "name": "context_tool"
            }
        }
        
        result = await full_security_framework.process_request(request, authenticated_context)
        
        # Check that context was enriched and propagated
        final_context = result["context"]
        
        # Should have original context
        assert final_context["user_id"] == authenticated_context["user_id"]
        assert final_context["ip_address"] == authenticated_context["ip_address"]
        
        # Should have enriched context from security layers
        assert "roles" in final_context
        assert "permissions" in final_context
        assert "session_id" in final_context
        assert "security_level" in final_context
    
    @pytest.mark.integration
    @pytest.mark.security
    async def test_performance_with_all_layers(self, full_security_framework, authenticated_context, benchmark):
        """Test performance with all security layers enabled."""
        request = {
            "jsonrpc": "2.0",
            "id": "perf_test",
            "method": "tools/list",
            "params": {}
        }
        
        async def process_request():
            return await full_security_framework.process_request(request, authenticated_context)
        
        # Benchmark with all layers
        result = await process_request()
        
        # Should complete within reasonable time
        processing_time = result["security_metadata"]["processing_time_ms"]
        assert processing_time < 100  # Less than 100ms
        
        # All layers should be processed
        layers_processed = result["security_metadata"]["layers_processed"]
        expected_layers = [
            "input_validation", "authentication", "authorization",
            "rate_limiting", "encryption", "ai_immune", "audit"
        ]
        
        for layer in expected_layers:
            assert layer in layers_processed
    
    @pytest.mark.integration
    @pytest.mark.security
    async def test_concurrent_layer_processing(self, full_security_framework, authenticated_context):
        """Test concurrent processing through security layers."""
        requests = [
            {
                "jsonrpc": "2.0",
                "id": f"concurrent_{i}",
                "method": "tools/list",
                "params": {}
            }
            for i in range(5)
        ]
        
        # Process requests concurrently
        tasks = [
            full_security_framework.process_request(request, authenticated_context)
            for request in requests
        ]
        
        results = await asyncio.gather(*tasks)
        
        # All requests should be processed successfully
        assert len(results) == 5
        
        for i, result in enumerate(results):
            assert result["request"]["id"] == f"concurrent_{i}"
            assert "security_metadata" in result
            
            # All layers should be processed for each request
            layers_processed = result["security_metadata"]["layers_processed"]
            assert len(layers_processed) > 0
    
    @pytest.mark.integration
    @pytest.mark.security
    async def test_security_level_escalation(self, full_security_framework):
        """Test security level escalation based on threat detection."""
        # Start with normal user
        normal_token = full_security_framework.authenticator.generate_token(
            user_id="escalation_user",
            roles=["user"],
            permissions=["mcp:read"]
        )
        
        normal_context = {
            "user_id": "escalation_user",
            "token": normal_token,
            "ip_address": "192.168.1.102"
        }
        
        # Make suspicious requests to trigger escalation
        suspicious_requests = [
            {
                "jsonrpc": "2.0",
                "id": f"suspicious_{i}",
                "method": "tools/call",
                "params": {
                    "command": f"suspicious_command_{i}",
                    "pattern": "unusual_pattern" * 10
                }
            }
            for i in range(3)
        ]
        
        results = []
        for request in suspicious_requests:
            try:
                result = await full_security_framework.process_request(request, normal_context)
                results.append(result)
            except SecurityError:
                # Some requests might be blocked
                pass
        
        # Security level should escalate
        if results:
            last_result = results[-1]
            security_level = last_result["security_metadata"]["security_level"]
            assert security_level in ["MEDIUM_RISK", "HIGH_RISK", "CRITICAL_RISK"]
    
    @pytest.mark.integration
    @pytest.mark.security
    async def test_adaptive_security_response(self, full_security_framework, authenticated_context):
        """Test adaptive security response based on threat patterns."""
        # Simulate attack pattern
        attack_requests = [
            {
                "jsonrpc": "2.0",
                "id": f"attack_{i}",
                "method": "tools/call",
                "params": {
                    "command": f"attack_vector_{i}",
                    "payload": "malicious_payload"
                }
            }
            for i in range(5)
        ]
        
        blocked_count = 0
        
        for request in attack_requests:
            try:
                await full_security_framework.process_request(request, authenticated_context)
            except SecurityError:
                blocked_count += 1
        
        # Should block most attack requests
        assert blocked_count >= 3
        
        # Security framework should adapt (lower thresholds, increase monitoring)
        metrics = full_security_framework.get_security_metrics()
        assert metrics["attacks_blocked"] >= blocked_count
    
    @pytest.mark.integration
    @pytest.mark.security
    async def test_cross_layer_data_sharing(self, full_security_framework, authenticated_context):
        """Test data sharing between security layers."""
        request = {
            "jsonrpc": "2.0",
            "id": "data_sharing_test",
            "method": "tools/call",
            "params": {
                "name": "data_tool",
                "args": {"data": "shared_data"}
            }
        }
        
        result = await full_security_framework.process_request(request, authenticated_context)
        
        # Check that layers shared relevant data
        metadata = result["security_metadata"]
        
        # Authentication layer should share user info
        assert "user_roles" in metadata
        assert "user_permissions" in metadata
        
        # Rate limiting should share usage info
        assert "rate_limit_status" in metadata
        
        # AI immune system should share threat assessment
        assert "threat_score" in metadata
    
    @pytest.mark.integration
    @pytest.mark.security
    async def test_security_policy_enforcement_across_layers(self, full_security_framework, authenticated_context):
        """Test security policy enforcement across multiple layers."""
        # Add cross-layer security policy
        policy = {
            "name": "high_security_policy",
            "rules": [
                {
                    "condition": "threat_score > 0.7",
                    "action": "require_additional_auth"
                },
                {
                    "condition": "method == 'tools/call' AND user_role == 'guest'",
                    "action": "block"
                }
            ]
        }
        
        full_security_framework.add_security_policy(policy)
        
        # Test with guest user
        guest_token = full_security_framework.authenticator.generate_token(
            user_id="guest_user",
            roles=["guest"],
            permissions=["mcp:read"]
        )
        
        guest_context = {
            "user_id": "guest_user",
            "token": guest_token,
            "ip_address": "192.168.1.103"
        }
        
        restricted_request = {
            "jsonrpc": "2.0",
            "id": "policy_test",
            "method": "tools/call",
            "params": {
                "name": "restricted_tool"
            }
        }
        
        # Should be blocked by policy
        with pytest.raises(SecurityError, match="Blocked by security policy"):
            await full_security_framework.process_request(restricted_request, guest_context)
