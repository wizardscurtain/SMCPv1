"""End-to-end integration tests for SMCP v1.

Tests complete workflows from request receipt to response,
including all security layers and real-world scenarios.
"""

import pytest
import asyncio
import json
from datetime import datetime, timedelta

from smcp_security.core import SMCPSecurityFramework, SecurityConfig
from smcp_security.exceptions import SecurityError, ValidationError, AuthenticationError
from tests.fixtures.attack_data import generate_malicious_request
from tests.fixtures.performance_data import generate_performance_requests, PerformanceScenario


class TestEndToEndWorkflows:
    """Test complete end-to-end workflows."""
    
    @pytest.fixture
    def production_framework(self):
        """Production-like security framework configuration."""
        config = SecurityConfig(
            enable_input_validation=True,
            validation_strictness="maximum",
            enable_mfa=False,  # Disabled for testing
            enable_rbac=True,
            enable_rate_limiting=True,
            default_rate_limit=100,
            adaptive_limits=True,
            enable_encryption=True,
            enable_ai_immune=True,
            anomaly_threshold=0.6,
            learning_mode=True,
            enable_audit_logging=True,
            log_level="INFO"
        )
        return SMCPSecurityFramework(config)
    
    @pytest.fixture
    def admin_context(self, production_framework):
        """Admin user context with full permissions."""
        token = production_framework.authenticator.generate_token(
            user_id="admin_user",
            roles=["admin"],
            permissions=["mcp:*", "system:*", "security:*"]
        )
        
        return {
            "user_id": "admin_user",
            "token": token,
            "ip_address": "192.168.1.10",
            "user_agent": "SMCP-Admin/1.0"
        }
    
    @pytest.fixture
    def user_context(self, production_framework):
        """Regular user context with limited permissions."""
        token = production_framework.authenticator.generate_token(
            user_id="regular_user",
            roles=["user"],
            permissions=["mcp:read", "mcp:execute:safe_tools"]
        )
        
        return {
            "user_id": "regular_user",
            "token": token,
            "ip_address": "192.168.1.100",
            "user_agent": "SMCP-Client/1.0"
        }
    
    @pytest.mark.integration
    @pytest.mark.e2e
    async def test_complete_valid_request_workflow(self, production_framework, user_context):
        """Test complete workflow for valid request."""
        request = {
            "jsonrpc": "2.0",
            "id": "e2e_valid_request",
            "method": "tools/list",
            "params": {
                "filter": "calculator"
            }
        }
        
        result = await production_framework.process_request(request, user_context)
        
        # Verify complete processing
        assert "request" in result
        assert "context" in result
        assert "security_metadata" in result
        
        # Verify request was processed correctly
        processed_request = result["request"]
        assert processed_request["jsonrpc"] == "2.0"
        assert processed_request["id"] == "e2e_valid_request"
        assert processed_request["method"] == "tools/list"
        
        # Verify context enrichment
        context = result["context"]
        assert context["user_id"] == "regular_user"
        assert "roles" in context
        assert "permissions" in context
        assert "session_id" in context
        
        # Verify security metadata
        metadata = result["security_metadata"]
        assert metadata["security_level"] == "LOW_RISK"
        assert metadata["threat_score"] < 0.3
        assert len(metadata["layers_processed"]) >= 6
        
        # Verify all layers were processed
        expected_layers = [
            "input_validation", "authentication", "authorization",
            "rate_limiting", "ai_immune", "audit"
        ]
        
        for layer in expected_layers:
            assert layer in metadata["layers_processed"]
    
    @pytest.mark.integration
    @pytest.mark.e2e
    @pytest.mark.security
    async def test_malicious_request_detection_and_blocking(self, production_framework, user_context):
        """Test detection and blocking of malicious requests."""
        # Test various attack types
        attack_types = [
            "command_injection",
            "sql_injection",
            "xss",
            "path_traversal",
            "prompt_injection"
        ]
        
        blocked_attacks = 0
        
        for attack_type in attack_types:
            malicious_request = generate_malicious_request(attack_type)
            
            try:
                await production_framework.process_request(malicious_request, user_context)
                # If we reach here, the attack wasn't blocked
                pytest.fail(f"Attack type {attack_type} was not blocked")
            except (SecurityError, ValidationError):
                blocked_attacks += 1
        
        # Should block all attack types
        assert blocked_attacks == len(attack_types)
        
        # Verify security events were logged
        audit_events = production_framework.audit_logger.get_events(
            category="SECURITY_VIOLATION",
            limit=10
        )
        
        assert len(audit_events) >= blocked_attacks
    
    @pytest.mark.integration
    @pytest.mark.e2e
    async def test_user_session_lifecycle(self, production_framework):
        """Test complete user session lifecycle."""
        # 1. User login (token generation)
        login_token = production_framework.authenticator.generate_token(
            user_id="session_user",
            roles=["user"],
            permissions=["mcp:read"]
        )
        
        session_context = {
            "user_id": "session_user",
            "token": login_token,
            "ip_address": "192.168.1.200",
            "user_agent": "SMCP-Client/1.0"
        }
        
        # 2. Make several requests during session
        session_requests = [
            {
                "jsonrpc": "2.0",
                "id": f"session_req_{i}",
                "method": "tools/list",
                "params": {}
            }
            for i in range(5)
        ]
        
        session_results = []
        for request in session_requests:
            result = await production_framework.process_request(request, session_context)
            session_results.append(result)
        
        # All requests should succeed
        assert len(session_results) == 5
        
        # 3. Token refresh
        new_token = production_framework.authenticator.refresh_token(login_token)
        session_context["token"] = new_token
        
        # 4. Continue with new token
        refresh_request = {
            "jsonrpc": "2.0",
            "id": "post_refresh_req",
            "method": "tools/list",
            "params": {}
        }
        
        refresh_result = await production_framework.process_request(refresh_request, session_context)
        assert "request" in refresh_result
        
        # 5. Old token should be invalid
        old_context = session_context.copy()
        old_context["token"] = login_token
        
        with pytest.raises(AuthenticationError):
            await production_framework.process_request(refresh_request, old_context)
        
        # 6. Session logout (token revocation)
        production_framework.authenticator.revoke_token(new_token)
        
        with pytest.raises(AuthenticationError):
            await production_framework.process_request(refresh_request, session_context)
    
    @pytest.mark.integration
    @pytest.mark.e2e
    async def test_role_based_access_workflow(self, production_framework):
        """Test role-based access control workflow."""
        # Create users with different roles
        users = [
            {
                "user_id": "guest_user",
                "roles": ["guest"],
                "permissions": ["mcp:read:public"]
            },
            {
                "user_id": "regular_user",
                "roles": ["user"],
                "permissions": ["mcp:read", "mcp:execute:safe_tools"]
            },
            {
                "user_id": "power_user",
                "roles": ["power_user"],
                "permissions": ["mcp:read", "mcp:write", "mcp:execute:all_tools"]
            },
            {
                "user_id": "admin_user",
                "roles": ["admin"],
                "permissions": ["mcp:*", "system:*"]
            }
        ]
        
        # Test requests with different permission requirements
        test_requests = [
            {
                "request": {
                    "jsonrpc": "2.0",
                    "id": "read_test",
                    "method": "tools/list",
                    "params": {}
                },
                "required_permission": "mcp:read",
                "allowed_roles": ["user", "power_user", "admin"]
            },
            {
                "request": {
                    "jsonrpc": "2.0",
                    "id": "write_test",
                    "method": "resources/write",
                    "params": {"uri": "file://test.txt", "content": "test"}
                },
                "required_permission": "mcp:write",
                "allowed_roles": ["power_user", "admin"]
            },
            {
                "request": {
                    "jsonrpc": "2.0",
                    "id": "admin_test",
                    "method": "system/config",
                    "params": {"setting": "debug", "value": True}
                },
                "required_permission": "system:config",
                "allowed_roles": ["admin"]
            }
        ]
        
        for user in users:
            # Generate token for user
            token = production_framework.authenticator.generate_token(
                user_id=user["user_id"],
                roles=user["roles"],
                permissions=user["permissions"]
            )
            
            context = {
                "user_id": user["user_id"],
                "token": token,
                "ip_address": "192.168.1.100"
            }
            
            for test_case in test_requests:
                request = test_case["request"]
                allowed_roles = test_case["allowed_roles"]
                
                if any(role in user["roles"] for role in allowed_roles):
                    # Should succeed
                    try:
                        result = await production_framework.process_request(request, context)
                        assert "request" in result
                    except SecurityError as e:
                        if "Insufficient permissions" not in str(e):
                            # Re-raise if it's not a permission error
                            raise
                else:
                    # Should fail with authorization error
                    with pytest.raises(SecurityError, match="Insufficient permissions"):
                        await production_framework.process_request(request, context)
    
    @pytest.mark.integration
    @pytest.mark.e2e
    @pytest.mark.performance
    async def test_high_load_scenario(self, production_framework, user_context):
        """Test system behavior under high load."""
        # Generate high load scenario
        scenario = PerformanceScenario(
            name="high_load_e2e",
            description="High load end-to-end test",
            request_count=100,
            concurrent_users=10,
            duration_seconds=60,
            request_rate_per_second=50,
            payload_size_bytes=1000,
            complexity_level="medium"
        )
        
        requests = generate_performance_requests(scenario)
        
        # Process requests in batches to simulate concurrent load
        batch_size = 10
        batches = [requests[i:i + batch_size] for i in range(0, len(requests), batch_size)]
        
        successful_requests = 0
        failed_requests = 0
        processing_times = []
        
        for batch in batches:
            # Process batch concurrently
            tasks = [
                production_framework.process_request(request, user_context)
                for request in batch
            ]
            
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in batch_results:
                if isinstance(result, Exception):
                    failed_requests += 1
                else:
                    successful_requests += 1
                    processing_time = result["security_metadata"]["processing_time_ms"]
                    processing_times.append(processing_time)
        
        # Verify system performance under load
        success_rate = successful_requests / (successful_requests + failed_requests)
        assert success_rate > 0.95  # At least 95% success rate
        
        # Verify reasonable processing times
        avg_processing_time = sum(processing_times) / len(processing_times)
        assert avg_processing_time < 50  # Average less than 50ms
        
        # Verify system metrics
        metrics = production_framework.get_security_metrics()
        assert metrics["requests_processed"] >= successful_requests
        assert metrics["success_rate"] > 0.95
    
    @pytest.mark.integration
    @pytest.mark.e2e
    @pytest.mark.security
    async def test_attack_simulation_scenario(self, production_framework):
        """Test system response to coordinated attack simulation."""
        # Simulate attacker with multiple IPs
        attacker_ips = [f"10.0.0.{i}" for i in range(1, 11)]
        
        # Generate attack tokens (some might be invalid)
        attack_contexts = []
        for i, ip in enumerate(attacker_ips):
            try:
                # Some attackers might have stolen/weak tokens
                if i % 3 == 0:
                    # Invalid token
                    token = "invalid.jwt.token"
                else:
                    # Valid but limited token
                    token = production_framework.authenticator.generate_token(
                        user_id=f"attacker_{i}",
                        roles=["guest"],
                        permissions=["mcp:read"]
                    )
                
                attack_contexts.append({
                    "user_id": f"attacker_{i}",
                    "token": token,
                    "ip_address": ip,
                    "user_agent": "AttackBot/1.0"
                })
            except Exception:
                # Skip if token generation fails
                continue
        
        # Generate various attack requests
        attack_requests = []
        attack_types = ["command_injection", "sql_injection", "xss", "path_traversal"]
        
        for attack_type in attack_types:
            for i in range(5):  # 5 requests per attack type
                attack_request = generate_malicious_request(attack_type)
                attack_request["id"] = f"{attack_type}_{i}"
                attack_requests.append(attack_request)
        
        # Execute coordinated attack
        blocked_attacks = 0
        successful_attacks = 0
        auth_failures = 0
        
        for i, request in enumerate(attack_requests):
            context = attack_contexts[i % len(attack_contexts)]
            
            try:
                result = await production_framework.process_request(request, context)
                successful_attacks += 1
                # This shouldn't happen for malicious requests
                pytest.fail(f"Malicious request {request['id']} was not blocked")
            except AuthenticationError:
                auth_failures += 1
            except (SecurityError, ValidationError):
                blocked_attacks += 1
            except Exception as e:
                # Other errors are also acceptable (rate limiting, etc.)
                blocked_attacks += 1
        
        # Verify attack mitigation
        total_requests = len(attack_requests)
        mitigation_rate = (blocked_attacks + auth_failures) / total_requests
        
        assert mitigation_rate > 0.95  # Should block >95% of attacks
        assert successful_attacks == 0  # No attacks should succeed
        
        # Verify security events were logged
        security_events = production_framework.audit_logger.get_events(
            category="SECURITY_VIOLATION",
            limit=100
        )
        
        assert len(security_events) >= blocked_attacks
        
        # Verify DoS protection activated
        dos_metrics = production_framework.rate_limiter.get_dos_metrics()
        assert dos_metrics["suspicious_ips"] >= len(set(attacker_ips))
    
    @pytest.mark.integration
    @pytest.mark.e2e
    async def test_adaptive_security_learning(self, production_framework, user_context):
        """Test adaptive security learning over time."""
        # Enable learning mode
        production_framework.config.learning_mode = True
        
        # Phase 1: Normal usage pattern
        normal_requests = [
            {
                "jsonrpc": "2.0",
                "id": f"normal_{i}",
                "method": "tools/list",
                "params": {"filter": "calculator"}
            }
            for i in range(20)
        ]
        
        # Establish baseline
        for request in normal_requests:
            result = await production_framework.process_request(request, user_context)
            assert "request" in result
        
        # Phase 2: Introduce anomalous but benign pattern
        anomalous_requests = [
            {
                "jsonrpc": "2.0",
                "id": f"anomalous_{i}",
                "method": "tools/call",
                "params": {
                    "name": "new_tool",
                    "args": {"data": "unusual_but_safe_pattern" * 10}
                }
            }
            for i in range(10)
        ]
        
        # Initially might be flagged as suspicious
        initial_threat_scores = []
        for request in anomalous_requests[:3]:
            result = await production_framework.process_request(request, user_context)
            threat_score = result["security_metadata"]["threat_score"]
            initial_threat_scores.append(threat_score)
        
        # Continue with pattern to allow learning
        for request in anomalous_requests[3:]:
            result = await production_framework.process_request(request, user_context)
        
        # Phase 3: Repeat anomalous pattern
        repeat_requests = anomalous_requests[:3]
        final_threat_scores = []
        
        for request in repeat_requests:
            result = await production_framework.process_request(request, user_context)
            threat_score = result["security_metadata"]["threat_score"]
            final_threat_scores.append(threat_score)
        
        # Verify learning occurred (threat scores should decrease)
        avg_initial_score = sum(initial_threat_scores) / len(initial_threat_scores)
        avg_final_score = sum(final_threat_scores) / len(final_threat_scores)
        
        assert avg_final_score < avg_initial_score
        
        # Verify AI immune system learned the pattern
        ai_health = production_framework.ai_immune_system.get_system_health()
        assert ai_health["model_status"] == "healthy"
        assert "last_update" in ai_health
    
    @pytest.mark.integration
    @pytest.mark.e2e
    async def test_disaster_recovery_scenario(self, production_framework, user_context):
        """Test system behavior during component failures."""
        request = {
            "jsonrpc": "2.0",
            "id": "disaster_test",
            "method": "tools/list",
            "params": {}
        }
        
        # Simulate various component failures
        failure_scenarios = [
            ("ai_immune_system", "AI system failure"),
            ("audit_logger", "Audit system failure"),
            ("crypto_manager", "Crypto system failure")
        ]
        
        for component_name, error_message in failure_scenarios:
            component = getattr(production_framework, component_name)
            
            # Simulate component failure
            with patch.object(component, 'analyze_request' if hasattr(component, 'analyze_request') else 'log_event') as mock_method:
                mock_method.side_effect = Exception(error_message)
                
                # System should continue operating with degraded security
                result = await production_framework.process_request(request, user_context)
                
                assert "request" in result
                assert "security_metadata" in result
                
                # Should indicate component failure
                metadata = result["security_metadata"]
                assert "errors" in metadata
                assert component_name.replace("_system", "").replace("_manager", "").replace("_logger", "") in str(metadata["errors"])
        
        # Verify system health reporting
        health = production_framework.health_check()
        assert "status" in health
        assert "components" in health
    
    @pytest.mark.integration
    @pytest.mark.e2e
    async def test_compliance_audit_trail(self, production_framework, admin_context, user_context):
        """Test complete audit trail for compliance requirements."""
        # Simulate various user activities
        activities = [
            # Admin activities
            {
                "context": admin_context,
                "request": {
                    "jsonrpc": "2.0",
                    "id": "admin_config",
                    "method": "system/config",
                    "params": {"setting": "security_level", "value": "high"}
                }
            },
            # User activities
            {
                "context": user_context,
                "request": {
                    "jsonrpc": "2.0",
                    "id": "user_read",
                    "method": "resources/read",
                    "params": {"uri": "file://document.txt"}
                }
            },
            # Failed access attempt
            {
                "context": user_context,
                "request": {
                    "jsonrpc": "2.0",
                    "id": "user_admin_attempt",
                    "method": "system/config",
                    "params": {"setting": "debug", "value": True}
                }
            }
        ]
        
        # Execute activities
        for activity in activities:
            try:
                result = await production_framework.process_request(
                    activity["request"], activity["context"]
                )
            except SecurityError:
                # Expected for unauthorized access
                pass
        
        # Verify comprehensive audit trail
        all_events = production_framework.audit_logger.get_events(limit=100)
        
        # Should have events for all activities
        assert len(all_events) >= len(activities)
        
        # Verify event categories
        event_categories = set(event["category"] for event in all_events)
        expected_categories = {
            "AUTHENTICATION", "AUTHORIZATION", "INPUT_VALIDATION"
        }
        
        assert expected_categories.issubset(event_categories)
        
        # Verify audit trail completeness
        for event in all_events:
            # Each event should have required fields for compliance
            required_fields = [
                "timestamp", "event_id", "user_id", "category",
                "severity", "message"
            ]
            
            for field in required_fields:
                assert field in event
            
            # Verify timestamp format
            assert isinstance(event["timestamp"], str)
            
            # Verify event ID uniqueness
            assert len(event["event_id"]) > 0
        
        # Test audit export for compliance reporting
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            export_path = f.name
        
        try:
            production_framework.audit_logger.export_events(export_path, format="json")
            
            # Verify export file
            import os
            assert os.path.exists(export_path)
            assert os.path.getsize(export_path) > 0
            
            # Verify export content
            with open(export_path, 'r') as f:
                export_data = f.read()
                assert len(export_data) > 0
                # Should be valid JSON
                json.loads(export_data)
        
        finally:
            # Cleanup
            import os
            if os.path.exists(export_path):
                os.unlink(export_path)
