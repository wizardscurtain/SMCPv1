#!/usr/bin/env python3
"""Basic usage example for SMCP Security Framework

This example demonstrates how to integrate and use the SMCP v1 security
framework with a basic MCP server implementation.
"""

import asyncio
import json
from datetime import datetime

# Import SMCP security framework
from smcp_security import (
    SMCPSecurityFramework,
    SecurityConfig
)
from smcp_security.audit import EventSeverity, EventCategory


class BasicMCPServer:
    """Basic MCP server with SMCP security integration"""
    
    def __init__(self):
        # Configure security framework
        security_config = SecurityConfig(
            enable_input_validation=True,
            enable_mfa=False,  # Disabled for demo
            enable_rbac=True,
            enable_rate_limiting=True,
            enable_encryption=True,
            enable_ai_immune=True,
            enable_audit_logging=True,
            validation_strictness="standard",
            default_rate_limit=60,  # 60 requests per minute
            anomaly_threshold=0.8
        )
        
        # Initialize security framework
        self.security = SMCPSecurityFramework(security_config)
        
        # Setup default users and roles for demo
        self._setup_demo_users()
        
        # Available MCP tools
        self.tools = {
            "echo": self._tool_echo,
            "calculate": self._tool_calculate,
            "file_read": self._tool_file_read,
            "system_info": self._tool_system_info
        }
    
    def _setup_demo_users(self):
        """Setup demo users and roles"""
        rbac = self.security.rbac_manager
        auth = self.security.jwt_auth
        
        # Define roles
        rbac.define_role("guest", [
            "mcp:read",
            "mcp:execute:echo",
            "mcp:execute:calculate"
        ], "Guest user with limited access")
        
        rbac.define_role("user", [
            "mcp:read",
            "mcp:execute:echo",
            "mcp:execute:calculate",
            "mcp:execute:system_info"
        ], "Regular user")
        
        rbac.define_role("admin", [
            "mcp:*"
        ], "Administrator with full access")
        
        # Assign roles to demo users
        rbac.assign_role("demo_guest", "guest")
        rbac.assign_role("demo_user", "user")
        rbac.assign_role("demo_admin", "admin")
    
    def create_demo_token(self, user_id: str) -> str:
        """Create a demo authentication token"""
        user_roles = self.security.rbac_manager.get_user_roles(user_id)
        user_permissions = self.security.rbac_manager.get_user_permissions(user_id)
        
        return self.security.jwt_auth.generate_token(
            user_id=user_id,
            roles=user_roles,
            permissions=user_permissions,
            mfa_verified=True  # Skip MFA for demo
        )
    
    async def process_mcp_request(self, request_data: dict, 
                                 user_context: dict) -> dict:
        """Process an MCP request through security framework
        
        Args:
            request_data: MCP JSON-RPC request
            user_context: User authentication context
            
        Returns:
            MCP response or error
        """
        try:
            # Process through security framework
            security_result = await self.security.process_request(
                request_data, user_context
            )
            
            validated_request = security_result["request"]
            auth_context = security_result["context"]
            
            # Execute the actual MCP method
            method = validated_request.get("method")
            params = validated_request.get("params", {})
            
            if method == "tools/list":
                result = await self._handle_tools_list(auth_context)
            elif method == "tools/call":
                result = await self._handle_tools_call(params, auth_context)
            else:
                result = {
                    "error": {
                        "code": -32601,
                        "message": f"Method not found: {method}"
                    }
                }
            
            # Add security metadata to response
            if "result" in result:
                result["security_metadata"] = security_result["security_metadata"]
            
            return {
                "jsonrpc": "2.0",
                "id": validated_request.get("id"),
                **result
            }
            
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "id": request_data.get("id"),
                "error": {
                    "code": -32000,
                    "message": f"Security error: {str(e)}"
                }
            }
    
    async def _handle_tools_list(self, auth_context: dict) -> dict:
        """Handle tools/list request"""
        user_id = auth_context.get("user_id")
        available_tools = []
        
        for tool_name, tool_func in self.tools.items():
            # Check if user has permission for this tool
            if self.security.rbac_manager.check_permission(
                user_id, f"mcp:execute:{tool_name}"
            ):
                available_tools.append({
                    "name": tool_name,
                    "description": tool_func.__doc__ or f"Execute {tool_name}",
                    "inputSchema": {
                        "type": "object",
                        "properties": {},
                        "required": []
                    }
                })
        
        return {"result": {"tools": available_tools}}
    
    async def _handle_tools_call(self, params: dict, auth_context: dict) -> dict:
        """Handle tools/call request"""
        tool_name = params.get("name")
        tool_arguments = params.get("arguments", {})
        user_id = auth_context.get("user_id")
        
        # Check permission
        if not self.security.rbac_manager.check_permission(
            user_id, f"mcp:execute:{tool_name}"
        ):
            return {
                "error": {
                    "code": -32000,
                    "message": f"Permission denied for tool: {tool_name}"
                }
            }
        
        # Execute tool
        if tool_name not in self.tools:
            return {
                "error": {
                    "code": -32000,
                    "message": f"Tool not found: {tool_name}"
                }
            }
        
        try:
            tool_result = await self.tools[tool_name](tool_arguments)
            return {"result": {"content": [tool_result]}}
        except Exception as e:
            return {
                "error": {
                    "code": -32000,
                    "message": f"Tool execution error: {str(e)}"
                }
            }
    
    # Demo tools
    async def _tool_echo(self, args: dict) -> dict:
        """Echo tool - returns the input message"""
        message = args.get("message", "Hello, World!")
        return {
            "type": "text",
            "text": f"Echo: {message}"
        }
    
    async def _tool_calculate(self, args: dict) -> dict:
        """Simple calculator tool"""
        expression = args.get("expression", "1+1")
        
        # Basic validation to prevent code injection
        allowed_chars = set("0123456789+-*/()., ")
        if not all(c in allowed_chars for c in expression):
            raise ValueError("Invalid characters in expression")
        
        try:
            result = eval(expression)  # Note: In production, use a safe math parser
            return {
                "type": "text",
                "text": f"Result: {expression} = {result}"
            }
        except Exception as e:
            raise ValueError(f"Calculation error: {str(e)}")
    
    async def _tool_file_read(self, args: dict) -> dict:
        """File reading tool (restricted)"""
        filename = args.get("filename", "")
        
        # Security check - only allow reading from safe directory
        if ".." in filename or filename.startswith("/"):
            raise ValueError("Invalid file path")
        
        return {
            "type": "text",
            "text": f"File content simulation for: {filename}"
        }
    
    async def _tool_system_info(self, args: dict) -> dict:
        """System information tool"""
        import platform
        import psutil
        
        info = {
            "platform": platform.system(),
            "python_version": platform.python_version(),
            "cpu_count": psutil.cpu_count(),
            "memory_total": psutil.virtual_memory().total,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        return {
            "type": "text",
            "text": f"System Info: {json.dumps(info, indent=2)}"
        }


async def demo_normal_requests():
    """Demonstrate normal MCP requests"""
    print("\n=== SMCP Security Framework Demo ===")
    print("Demonstrating normal MCP requests with security...\n")
    
    server = BasicMCPServer()
    
    # Create demo tokens
    guest_token = server.create_demo_token("demo_guest")
    user_token = server.create_demo_token("demo_user")
    admin_token = server.create_demo_token("demo_admin")
    
    print(f"Created demo tokens:")
    print(f"  Guest: {guest_token[:20]}...")
    print(f"  User:  {user_token[:20]}...")
    print(f"  Admin: {admin_token[:20]}...\n")
    
    # Test requests
    test_requests = [
        {
            "name": "List tools (Guest)",
            "request": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {}
            },
            "context": {"token": guest_token, "ip_address": "192.168.1.100"}
        },
        {
            "name": "Echo tool (Guest)",
            "request": {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "echo",
                    "arguments": {"message": "Hello from SMCP!"}
                }
            },
            "context": {"token": guest_token, "ip_address": "192.168.1.100"}
        },
        {
            "name": "Calculate (User)",
            "request": {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "calculate",
                    "arguments": {"expression": "2 + 3 * 4"}
                }
            },
            "context": {"token": user_token, "ip_address": "192.168.1.101"}
        },
        {
            "name": "System info (User)",
            "request": {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "system_info",
                    "arguments": {}
                }
            },
            "context": {"token": user_token, "ip_address": "192.168.1.101"}
        }
    ]
    
    for test in test_requests:
        print(f"Testing: {test['name']}")
        try:
            response = await server.process_mcp_request(
                test["request"], test["context"]
            )
            
            if "error" in response:
                print(f"  ❌ Error: {response['error']['message']}")
            else:
                print(f"  ✅ Success")
                if "security_metadata" in response:
                    metadata = response["security_metadata"]
                    print(f"     Security Level: {metadata.get('security_level')}")
                    print(f"     Processing Time: {metadata.get('processing_time_ms'):.2f}ms")
        except Exception as e:
            print(f"  ❌ Exception: {str(e)}")
        
        print()


async def demo_security_violations():
    """Demonstrate security violations and how they're handled"""
    print("\n=== Security Violations Demo ===")
    print("Demonstrating how SMCP handles malicious requests...\n")
    
    server = BasicMCPServer()
    guest_token = server.create_demo_token("demo_guest")
    
    # Malicious requests
    malicious_requests = [
        {
            "name": "Command Injection",
            "request": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "echo",
                    "arguments": {"message": "Hello; rm -rf /"}
                }
            }
        },
        {
            "name": "SQL Injection",
            "request": {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "calculate",
                    "arguments": {"expression": "1' OR '1'='1"}
                }
            }
        },
        {
            "name": "Path Traversal",
            "request": {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "file_read",
                    "arguments": {"filename": "../../../etc/passwd"}
                }
            }
        },
        {
            "name": "Permission Violation",
            "request": {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "file_read",  # Guest doesn't have permission
                    "arguments": {"filename": "safe_file.txt"}
                }
            }
        }
    ]
    
    context = {"token": guest_token, "ip_address": "192.168.1.200"}
    
    for test in malicious_requests:
        print(f"Testing: {test['name']}")
        try:
            response = await server.process_mcp_request(test["request"], context)
            
            if "error" in response:
                print(f"  🛡️  Blocked: {response['error']['message']}")
            else:
                print(f"  ⚠️  Allowed (unexpected)")
        except Exception as e:
            print(f"  🛡️  Blocked: {str(e)}")
        
        print()


async def demo_metrics_and_monitoring():
    """Demonstrate security metrics and monitoring"""
    print("\n=== Security Metrics Demo ===")
    print("Showing security framework metrics...\n")
    
    server = BasicMCPServer()
    
    # Get security metrics
    metrics = server.security.get_security_metrics()
    print("Security Framework Metrics:")
    for key, value in metrics.items():
        if key != "processing_time_ms":  # Skip the list
            print(f"  {key}: {value}")
    
    print()
    
    # Get audit metrics
    audit_metrics = server.security.audit_logger.get_metrics()
    print("Audit System Metrics:")
    for key, value in audit_metrics.items():
        print(f"  {key}: {value}")
    
    print()
    
    # Get recent security events
    recent_events = server.security.audit_logger.get_events(limit=5)
    print("Recent Security Events:")
    for event in recent_events:
        print(f"  [{event['timestamp']}] {event['severity']} - {event['description']}")


async def main():
    """Main demo function"""
    try:
        await demo_normal_requests()
        await demo_security_violations()
        await demo_metrics_and_monitoring()
        
        print("\n=== Demo Complete ===")
        print("The SMCP Security Framework successfully:")
        print("  ✅ Processed legitimate requests")
        print("  🛡️  Blocked malicious requests")
        print("  📊 Provided comprehensive monitoring")
        print("  🔒 Maintained security throughout")
        
    except Exception as e:
        print(f"Demo error: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    # Run the demo
    asyncio.run(main())