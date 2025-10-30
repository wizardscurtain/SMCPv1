#!/usr/bin/env python3
"""Advanced usage example for SMCP Security Framework

This example demonstrates advanced features including:
- AI immune system training
- Custom security policies
- Real-time threat monitoring
- Security incident response
"""

import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any

from smcp_security import (
    SMCPSecurityFramework,
    SecurityConfig
)
from smcp_security.audit import EventSeverity, EventCategory
from smcp_security.authorization import AuthorizationContext


class AdvancedMCPServer:
    """Advanced MCP server with comprehensive security features"""
    
    def __init__(self):
        # Advanced security configuration
        security_config = SecurityConfig(
            enable_input_validation=True,
            enable_mfa=True,
            enable_rbac=True,
            enable_rate_limiting=True,
            enable_encryption=True,
            enable_ai_immune=True,
            enable_audit_logging=True,
            validation_strictness="maximum",
            default_rate_limit=30,  # Stricter rate limiting
            adaptive_limits=True,
            anomaly_threshold=0.7,  # More sensitive
            learning_mode=False
        )
        
        self.security = SMCPSecurityFramework(security_config)
        self._setup_advanced_security()
        
        # Threat monitoring
        self.active_threats = {}
        self.incident_response_enabled = True
        
        # Performance monitoring
        self.performance_metrics = {
            "request_count": 0,
            "avg_response_time": 0.0,
            "security_overhead": 0.0
        }
    
    def _setup_advanced_security(self):
        """Setup advanced security policies and roles"""
        rbac = self.security.rbac_manager
        
        # Define hierarchical roles with inheritance
        rbac.define_role("readonly", [
            "mcp:read",
            "mcp:execute:safe_tools"
        ], "Read-only access")
        
        rbac.define_role("developer", [
            "mcp:read",
            "mcp:write",
            "mcp:execute:dev_tools",
            "mcp:debug"
        ], "Developer access", parent_roles=["readonly"])
        
        rbac.define_role("security_analyst", [
            "security:read",
            "security:investigate",
            "audit:read"
        ], "Security analyst", parent_roles=["readonly"])
        
        rbac.define_role("admin", [
            "mcp:*",
            "security:*",
            "system:*"
        ], "Full administrator", parent_roles=["developer", "security_analyst"])
        
        # Add conditional permissions (time-based, IP-based)
        self._setup_conditional_permissions()
    
    def _setup_conditional_permissions(self):
        """Setup conditional access policies"""
        # Example: Admin access only during business hours from office IPs
        # This would be implemented in a production system
        pass
    
    async def train_ai_immune_system(self, training_data: List[Dict[str, Any]]):
        """Train the AI immune system with normal request patterns"""
        print("Training AI immune system...")
        
        if not training_data:
            # Generate synthetic training data
            training_data = self._generate_training_data()
        
        await self.security.train_ai_immune_system(training_data)
        print(f"AI immune system trained with {len(training_data)} samples")
    
    def _generate_training_data(self) -> List[Dict[str, Any]]:
        """Generate synthetic training data for AI immune system"""
        training_requests = []
        
        # Normal tool list requests
        for i in range(50):
            training_requests.append({
                "jsonrpc": "2.0",
                "id": i,
                "method": "tools/list",
                "params": {}
            })
        
        # Normal tool calls
        normal_tools = ["echo", "calculate", "format_text", "get_time"]
        for i in range(100):
            tool = normal_tools[i % len(normal_tools)]
            training_requests.append({
                "jsonrpc": "2.0",
                "id": 50 + i,
                "method": "tools/call",
                "params": {
                    "name": tool,
                    "arguments": self._generate_normal_arguments(tool)
                }
            })
        
        return training_requests
    
    def _generate_normal_arguments(self, tool: str) -> Dict[str, Any]:
        """Generate normal arguments for training data"""
        if tool == "echo":
            messages = ["Hello", "Test message", "Good morning", "Status update"]
            return {"message": messages[hash(tool) % len(messages)]}
        elif tool == "calculate":
            expressions = ["2+2", "10*5", "100/4", "15-3"]
            return {"expression": expressions[hash(tool) % len(expressions)]}
        elif tool == "format_text":
            return {"text": "Sample text", "format": "uppercase"}
        elif tool == "get_time":
            return {"timezone": "UTC"}
        else:
            return {}
    
    async def process_request_with_monitoring(self, request_data: Dict[str, Any],
                                            user_context: Dict[str, Any]) -> Dict[str, Any]:
        """Process request with advanced monitoring and threat detection"""
        start_time = time.time()
        
        try:
            # Enhanced user context with additional security info
            enhanced_context = self._enhance_user_context(user_context)
            
            # Process through security framework
            security_result = await self.security.process_request(
                request_data, enhanced_context
            )
            
            # Check for active threats
            await self._check_active_threats(security_result)
            
            # Execute request (simplified for demo)
            response = await self._execute_request(security_result)
            
            # Update performance metrics
            processing_time = time.time() - start_time
            self._update_performance_metrics(processing_time)
            
            return response
            
        except Exception as e:
            # Enhanced error handling with incident creation
            await self._handle_security_incident(str(e), request_data, user_context)
            raise
    
    def _enhance_user_context(self, user_context: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance user context with additional security information"""
        enhanced = user_context.copy()
        
        # Add geolocation info (simulated)
        ip_address = user_context.get("ip_address", "")
        enhanced["geolocation"] = self._get_geolocation(ip_address)
        
        # Add device fingerprinting (simulated)
        user_agent = user_context.get("user_agent", "")
        enhanced["device_fingerprint"] = self._generate_device_fingerprint(user_agent)
        
        # Add risk score
        enhanced["risk_score"] = self._calculate_user_risk_score(enhanced)
        
        return enhanced
    
    def _get_geolocation(self, ip_address: str) -> Dict[str, str]:
        """Get geolocation for IP address (simulated)"""
        # In production, use a real geolocation service
        if ip_address.startswith("192.168."):
            return {"country": "US", "city": "Local", "is_vpn": False}
        elif ip_address.startswith("10."):
            return {"country": "US", "city": "Corporate", "is_vpn": False}
        else:
            return {"country": "Unknown", "city": "Unknown", "is_vpn": True}
    
    def _generate_device_fingerprint(self, user_agent: str) -> str:
        """Generate device fingerprint (simulated)"""
        import hashlib
        return hashlib.md5(user_agent.encode()).hexdigest()[:16]
    
    def _calculate_user_risk_score(self, context: Dict[str, Any]) -> float:
        """Calculate user risk score based on various factors"""
        risk_score = 0.0
        
        # VPN usage increases risk
        if context.get("geolocation", {}).get("is_vpn", False):
            risk_score += 0.3
        
        # Unknown geolocation increases risk
        if context.get("geolocation", {}).get("country") == "Unknown":
            risk_score += 0.2
        
        # Time-based risk (access outside business hours)
        current_hour = datetime.now().hour
        if current_hour < 6 or current_hour > 22:
            risk_score += 0.1
        
        return min(1.0, risk_score)
    
    async def _check_active_threats(self, security_result: Dict[str, Any]):
        """Check for active threats and update threat intelligence"""
        context = security_result["context"]
        user_id = context.get("user_id")
        threat_score = context.get("threat_score", 0.0)
        
        if threat_score > 0.8:
            threat_id = f"threat_{user_id}_{int(time.time())}"
            
            self.active_threats[threat_id] = {
                "user_id": user_id,
                "threat_score": threat_score,
                "first_detected": datetime.utcnow(),
                "last_activity": datetime.utcnow(),
                "request_count": 1,
                "status": "active"
            }
            
            if self.incident_response_enabled:
                await self._trigger_incident_response(threat_id)
    
    async def _trigger_incident_response(self, threat_id: str):
        """Trigger automated incident response"""
        threat = self.active_threats[threat_id]
        user_id = threat["user_id"]
        
        print(f"🚨 SECURITY ALERT: High-risk activity detected for user {user_id}")
        
        # Automated responses
        responses = []
        
        # Increase monitoring
        responses.append("Enhanced monitoring activated")
        
        # Reduce rate limits
        if hasattr(self.security, 'rate_limiter'):
            self.security.rate_limiter.add_to_blacklist(user_id)
            responses.append("User temporarily blacklisted")
        
        # Log incident
        self.security.audit_logger.log_security_event(
            "security_incident_triggered",
            user_id,
            {
                "threat_id": threat_id,
                "threat_score": threat["threat_score"],
                "automated_responses": responses
            },
            EventSeverity.CRITICAL,
            EventCategory.ANOMALY_DETECTION
        )
        
        print(f"   Automated responses: {', '.join(responses)}")
    
    async def _execute_request(self, security_result: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the validated request (simplified)"""
        request = security_result["request"]
        method = request.get("method")
        
        # Simulate request execution
        if method == "tools/list":
            result = {"tools": ["echo", "calculate", "secure_operation"]}
        elif method == "tools/call":
            tool_name = request.get("params", {}).get("name", "unknown")
            result = {"content": [{"type": "text", "text": f"Executed {tool_name} securely"}]}
        else:
            result = {"message": "Request processed"}
        
        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "result": result,
            "security_metadata": security_result["security_metadata"]
        }
    
    def _update_performance_metrics(self, processing_time: float):
        """Update performance metrics"""
        self.performance_metrics["request_count"] += 1
        
        # Update average response time
        count = self.performance_metrics["request_count"]
        current_avg = self.performance_metrics["avg_response_time"]
        self.performance_metrics["avg_response_time"] = (
            (current_avg * (count - 1) + processing_time) / count
        )
    
    async def _handle_security_incident(self, error_message: str, 
                                      request_data: Dict[str, Any],
                                      user_context: Dict[str, Any]):
        """Handle security incidents with detailed logging"""
        incident_id = f"incident_{int(time.time())}"
        
        # Log detailed incident information
        self.security.audit_logger.log_security_event(
            "security_incident",
            user_context.get("user_id"),
            {
                "incident_id": incident_id,
                "error_message": error_message,
                "request_method": request_data.get("method"),
                "request_size": len(json.dumps(request_data)),
                "ip_address": user_context.get("ip_address"),
                "user_agent": user_context.get("user_agent")
            },
            EventSeverity.ERROR,
            EventCategory.SYSTEM
        )
    
    def get_security_dashboard(self) -> Dict[str, Any]:
        """Get comprehensive security dashboard data"""
        # Security metrics
        security_metrics = self.security.get_security_metrics()
        
        # Audit metrics
        audit_metrics = self.security.audit_logger.get_metrics()
        
        # Active threats
        active_threat_count = len([t for t in self.active_threats.values() 
                                 if t["status"] == "active"])
        
        # Recent incidents
        recent_incidents = self.security.audit_logger.get_incidents()
        
        return {
            "security_metrics": security_metrics,
            "audit_metrics": audit_metrics,
            "performance_metrics": self.performance_metrics,
            "active_threats": active_threat_count,
            "recent_incidents": len(recent_incidents),
            "system_status": "operational",
            "last_updated": datetime.utcnow().isoformat()
        }


async def demo_ai_training():
    """Demonstrate AI immune system training"""
    print("\n=== AI Immune System Training Demo ===")
    
    server = AdvancedMCPServer()
    
    # Train the AI immune system
    await server.train_ai_immune_system([])
    
    print("AI immune system training completed!")


async def demo_threat_detection():
    """Demonstrate advanced threat detection"""
    print("\n=== Advanced Threat Detection Demo ===")
    
    server = AdvancedMCPServer()
    await server.train_ai_immune_system([])
    
    # Create a demo token
    guest_token = server.security.jwt_auth.generate_token(
        user_id="suspicious_user",
        roles=["guest"],
        permissions=["mcp:read"],
        mfa_verified=True
    )
    
    # Simulate suspicious activity
    suspicious_requests = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "echo",
                "arguments": {"message": "rm -rf / && echo 'hacked'"}
            }
        },
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "calculate",
                "arguments": {"expression": "__import__('os').system('whoami')"}
            }
        }
    ]
    
    context = {
        "token": guest_token,
        "ip_address": "203.0.113.1",  # Suspicious IP
        "user_agent": "AttackBot/1.0"
    }
    
    for i, request in enumerate(suspicious_requests, 1):
        print(f"\nProcessing suspicious request {i}...")
        try:
            response = await server.process_request_with_monitoring(request, context)
            print(f"  Response: {response.get('result', 'No result')}")
        except Exception as e:
            print(f"  Blocked: {str(e)}")
    
    # Show active threats
    if server.active_threats:
        print(f"\nActive threats detected: {len(server.active_threats)}")
        for threat_id, threat in server.active_threats.items():
            print(f"  {threat_id}: Score {threat['threat_score']:.2f}")


async def demo_security_dashboard():
    """Demonstrate security dashboard"""
    print("\n=== Security Dashboard Demo ===")
    
    server = AdvancedMCPServer()
    
    # Simulate some activity
    await server.train_ai_immune_system([])
    
    # Get dashboard data
    dashboard = server.get_security_dashboard()
    
    print("Security Dashboard:")
    print(f"  System Status: {dashboard['system_status']}")
    print(f"  Total Requests: {dashboard['security_metrics']['requests_processed']}")
    print(f"  Attacks Blocked: {dashboard['security_metrics']['attacks_blocked']}")
    print(f"  Active Threats: {dashboard['active_threats']}")
    print(f"  Recent Incidents: {dashboard['recent_incidents']}")
    print(f"  Avg Response Time: {dashboard['performance_metrics']['avg_response_time']:.3f}s")
    print(f"  Last Updated: {dashboard['last_updated']}")


async def main():
    """Main advanced demo function"""
    print("🔒 SMCP Security Framework - Advanced Features Demo")
    print("=" * 60)
    
    try:
        await demo_ai_training()
        await demo_threat_detection()
        await demo_security_dashboard()
        
        print("\n" + "=" * 60)
        print("✅ Advanced Demo Complete!")
        print("\nAdvanced features demonstrated:")
        print("  🤖 AI immune system training")
        print("  🎯 Advanced threat detection")
        print("  🚨 Automated incident response")
        print("  📊 Comprehensive security dashboard")
        print("  🔍 Real-time monitoring")
        
    except Exception as e:
        print(f"\n❌ Demo error: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())