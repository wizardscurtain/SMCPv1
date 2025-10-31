#!/usr/bin/env python3
"""Basic usage example for SMCP Security framework"""

from smcp_security import SMCPSecurityFramework, SecurityConfig
from smcp_security.exceptions import SecurityError


def main():
    """Demonstrate basic SMCP security usage"""
    print("SMCP Security - Basic Usage Example")
    print("=" * 40)
    
    # Initialize security framework with default config
    security = SMCPSecurityFramework()
    print("✓ Security framework initialized")
    
    # Example MCP request
    mcp_request = {
        "jsonrpc": "2.0",
        "id": "req-123",
        "method": "tools/list",
        "params": {}
    }
    
    try:
        # Validate the request
        print("\n1. Validating MCP request...")
        validated_request = security.validate_request(mcp_request)
        print("✓ Request validation passed")
        
        # Simulate user authentication
        print("\n2. Authenticating user...")
        credentials = {
            "username": "demo_user",
            "password": "secure_password_123"
        }
        
        # In a real scenario, you'd verify these credentials
        user_token = security.create_user_session("demo_user")
        print(f"✓ User authenticated, token: {user_token[:20]}...")
        
        # Check authorization
        print("\n3. Checking authorization...")
        is_authorized = security.authorize_action("demo_user", "tools:list")
        print(f"✓ Authorization check: {'Allowed' if is_authorized else 'Denied'}")
        
        # Process secure request
        print("\n4. Processing secure request...")
        result = security.process_secure_request(
            request=validated_request,
            user_id="demo_user",
            session_token=user_token
        )
        print("✓ Request processed securely")
        print(f"Result: {result}")
        
        # Get security metrics
        print("\n5. Security metrics:")
        metrics = security.get_security_metrics()
        for key, value in metrics.items():
            print(f"  {key}: {value}")
        
    except SecurityError as e:
        print(f"❌ Security error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
    
    print("\n" + "=" * 40)
    print("Basic usage example completed")


def demonstrate_threat_detection():
    """Demonstrate AI-based threat detection"""
    print("\nThreat Detection Example")
    print("-" * 30)
    
    security = SMCPSecurityFramework()
    
    # Simulate malicious requests
    malicious_requests = [
        {
            "method": "tools/call",
            "params": {
                "name": "bash",
                "arguments": {"command": "rm -rf /"}
            }
        },
        {
            "method": "resources/read",
            "params": {
                "uri": "file:///etc/passwd"
            }
        },
        {
            "method": "prompts/get",
            "params": {
                "name": "../../../etc/hosts"
            }
        }
    ]
    
    for i, request in enumerate(malicious_requests, 1):
        try:
            print(f"\nTesting malicious request {i}:")
            print(f"Method: {request['method']}")
            
            # This should trigger security violations
            security.validate_request(request)
            print("⚠️  Request passed validation (unexpected)")
            
        except SecurityError as e:
            print(f"✓ Threat detected and blocked: {e}")
        except Exception as e:
            print(f"❌ Unexpected error: {e}")


def demonstrate_rate_limiting():
    """Demonstrate rate limiting functionality"""
    print("\nRate Limiting Example")
    print("-" * 25)
    
    # Configure with low rate limit for demo
    config = SecurityConfig(
        default_rate_limit=5,  # 5 requests per minute
        adaptive_limits=True
    )
    
    security = SMCPSecurityFramework(config=config)
    user_id = "rate_limit_test_user"
    
    # Simulate rapid requests
    for i in range(10):
        try:
            if security.rate_limiter.is_allowed(user_id):
                print(f"✓ Request {i+1}: Allowed")
            else:
                print(f"❌ Request {i+1}: Rate limited")
                
        except Exception as e:
            print(f"❌ Request {i+1}: Error - {e}")


if __name__ == "__main__":
    main()
    demonstrate_threat_detection()
    demonstrate_rate_limiting()
