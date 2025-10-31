"""Performance testing data and scenarios for SMCP v1.

This module provides test data and scenarios for performance benchmarking
and load testing of the security framework.
"""

from typing import Dict, List, Any, Generator
import time
import random
from dataclasses import dataclass
from faker import Faker

fake = Faker()
Faker.seed(42)


@dataclass
class PerformanceScenario:
    """Performance test scenario configuration."""
    name: str
    description: str
    request_count: int
    concurrent_users: int
    duration_seconds: int
    request_rate_per_second: int
    payload_size_bytes: int
    complexity_level: str  # simple, medium, complex


# Performance test scenarios
PERFORMANCE_TEST_SCENARIOS = [
    PerformanceScenario(
        name="smoke_test",
        description="Basic smoke test with minimal load",
        request_count=10,
        concurrent_users=1,
        duration_seconds=10,
        request_rate_per_second=1,
        payload_size_bytes=100,
        complexity_level="simple"
    ),
    PerformanceScenario(
        name="light_load",
        description="Light load testing with basic requests",
        request_count=100,
        concurrent_users=5,
        duration_seconds=60,
        request_rate_per_second=10,
        payload_size_bytes=500,
        complexity_level="simple"
    ),
    PerformanceScenario(
        name="medium_load",
        description="Medium load testing with moderate complexity",
        request_count=1000,
        concurrent_users=25,
        duration_seconds=300,
        request_rate_per_second=50,
        payload_size_bytes=2000,
        complexity_level="medium"
    ),
    PerformanceScenario(
        name="heavy_load",
        description="Heavy load testing with complex requests",
        request_count=5000,
        concurrent_users=100,
        duration_seconds=600,
        request_rate_per_second=200,
        payload_size_bytes=10000,
        complexity_level="complex"
    ),
    PerformanceScenario(
        name="stress_test",
        description="Stress testing to find breaking points",
        request_count=10000,
        concurrent_users=500,
        duration_seconds=1200,
        request_rate_per_second=1000,
        payload_size_bytes=50000,
        complexity_level="complex"
    ),
    PerformanceScenario(
        name="spike_test",
        description="Sudden spike in traffic",
        request_count=2000,
        concurrent_users=200,
        duration_seconds=120,
        request_rate_per_second=500,
        payload_size_bytes=5000,
        complexity_level="medium"
    ),
    PerformanceScenario(
        name="endurance_test",
        description="Long-running endurance test",
        request_count=50000,
        concurrent_users=50,
        duration_seconds=3600,
        request_rate_per_second=25,
        payload_size_bytes=1000,
        complexity_level="medium"
    )
]


def generate_performance_requests(scenario: PerformanceScenario) -> List[Dict[str, Any]]:
    """Generate requests for a performance test scenario.
    
    Args:
        scenario: Performance test scenario configuration
        
    Returns:
        List of MCP requests for testing
    """
    requests = []
    
    for i in range(scenario.request_count):
        request = create_performance_request(
            request_id=f"{scenario.name}-{i}",
            complexity=scenario.complexity_level,
            payload_size=scenario.payload_size_bytes
        )
        requests.append(request)
    
    return requests


def create_performance_request(request_id: str, 
                             complexity: str = "simple",
                             payload_size: int = 1000) -> Dict[str, Any]:
    """Create a single performance test request.
    
    Args:
        request_id: Unique request identifier
        complexity: Request complexity level
        payload_size: Target payload size in bytes
        
    Returns:
        MCP request dictionary
    """
    base_request = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {}
    }
    
    if complexity == "simple":
        base_request["method"] = random.choice([
            "tools/list", "resources/list", "prompts/list"
        ])
        base_request["params"] = {
            "filter": fake.word(),
            "limit": random.randint(1, 10)
        }
    
    elif complexity == "medium":
        base_request["method"] = random.choice([
            "tools/call", "resources/read", "prompts/get"
        ])
        base_request["params"] = {
            "name": fake.word(),
            "arguments": {
                "input": fake.text(max_nb_chars=payload_size // 4),
                "options": {
                    "format": random.choice(["json", "text", "xml"]),
                    "encoding": random.choice(["utf-8", "ascii", "base64"]),
                    "timeout": random.randint(1, 30)
                }
            },
            "metadata": {
                "timestamp": time.time(),
                "user_agent": fake.user_agent(),
                "session_id": fake.uuid4()
            }
        }
    
    elif complexity == "complex":
        base_request["method"] = "tools/call"
        base_request["params"] = {
            "name": fake.word(),
            "arguments": {
                "data": generate_complex_data(payload_size),
                "processing_options": {
                    "algorithms": [fake.word() for _ in range(5)],
                    "parameters": {
                        f"param_{i}": fake.random_number(digits=3)
                        for i in range(10)
                    },
                    "nested_config": {
                        "level1": {
                            "level2": {
                                "level3": {
                                    "data": fake.text(max_nb_chars=100)
                                }
                            }
                        }
                    }
                },
                "validation_rules": [
                    {
                        "field": fake.word(),
                        "type": random.choice(["string", "number", "boolean"]),
                        "required": fake.boolean(),
                        "constraints": {
                            "min_length": random.randint(1, 10),
                            "max_length": random.randint(50, 200),
                            "pattern": fake.regex()
                        }
                    }
                    for _ in range(5)
                ]
            },
            "metadata": {
                "timestamp": time.time(),
                "correlation_id": fake.uuid4(),
                "trace_id": fake.uuid4(),
                "user_context": {
                    "user_id": fake.uuid4(),
                    "roles": [fake.word() for _ in range(3)],
                    "permissions": [fake.word() for _ in range(10)],
                    "session_data": {
                        "created_at": time.time() - random.randint(0, 3600),
                        "last_activity": time.time() - random.randint(0, 300),
                        "ip_address": fake.ipv4(),
                        "user_agent": fake.user_agent()
                    }
                }
            }
        }
    
    return base_request


def generate_complex_data(target_size: int) -> Dict[str, Any]:
    """Generate complex nested data structure.
    
    Args:
        target_size: Target size in bytes
        
    Returns:
        Complex data structure
    """
    data = {
        "arrays": {
            "numbers": [fake.random_number(digits=5) for _ in range(50)],
            "strings": [fake.sentence() for _ in range(20)],
            "booleans": [fake.boolean() for _ in range(30)]
        },
        "objects": {
            f"object_{i}": {
                "id": fake.uuid4(),
                "name": fake.name(),
                "description": fake.text(max_nb_chars=200),
                "properties": {
                    f"prop_{j}": fake.word()
                    for j in range(5)
                },
                "nested": {
                    "level1": {
                        "level2": fake.text(max_nb_chars=100)
                    }
                }
            }
            for i in range(10)
        },
        "text_content": fake.text(max_nb_chars=target_size // 2),
        "binary_data": fake.binary(length=min(1000, target_size // 4)),
        "timestamps": {
            "created": time.time(),
            "modified": time.time() + random.randint(0, 3600),
            "accessed": time.time() + random.randint(0, 7200)
        }
    }
    
    return data


def create_load_test_data(users: int, 
                         requests_per_user: int,
                         complexity: str = "medium") -> Dict[str, List[Dict[str, Any]]]:
    """Create load test data for multiple users.
    
    Args:
        users: Number of concurrent users
        requests_per_user: Requests per user
        complexity: Request complexity level
        
    Returns:
        Dictionary mapping user IDs to their requests
    """
    load_data = {}
    
    for user_id in range(users):
        user_requests = []
        
        for req_id in range(requests_per_user):
            request = create_performance_request(
                request_id=f"user_{user_id}_req_{req_id}",
                complexity=complexity,
                payload_size=random.randint(500, 5000)
            )
            user_requests.append(request)
        
        load_data[f"user_{user_id}"] = user_requests
    
    return load_data


def generate_realistic_traffic_pattern(duration_minutes: int = 60) -> List[Dict[str, Any]]:
    """Generate realistic traffic pattern with peaks and valleys.
    
    Args:
        duration_minutes: Duration of traffic pattern in minutes
        
    Returns:
        List of timestamped requests
    """
    import math
    
    requests = []
    start_time = time.time()
    
    for minute in range(duration_minutes):
        # Simulate daily traffic pattern with peaks
        hour_of_day = (minute // 60) % 24
        
        # Peak hours: 9-11 AM and 2-4 PM
        if 9 <= hour_of_day <= 11 or 14 <= hour_of_day <= 16:
            base_rate = 100  # High traffic
        elif 6 <= hour_of_day <= 8 or 12 <= hour_of_day <= 13:
            base_rate = 60   # Medium traffic
        else:
            base_rate = 20   # Low traffic
        
        # Add some randomness and sine wave pattern
        sine_factor = math.sin(minute * math.pi / 30) * 0.3 + 1
        actual_rate = int(base_rate * sine_factor * random.uniform(0.7, 1.3))
        
        # Generate requests for this minute
        for req_num in range(actual_rate):
            timestamp = start_time + (minute * 60) + random.uniform(0, 60)
            
            request = create_performance_request(
                request_id=f"traffic_{minute}_{req_num}",
                complexity=random.choice(["simple", "medium", "complex"]),
                payload_size=random.randint(100, 10000)
            )
            request["timestamp"] = timestamp
            requests.append(request)
    
    return sorted(requests, key=lambda x: x["timestamp"])


def create_benchmark_suite() -> Dict[str, List[Dict[str, Any]]]:
    """Create a comprehensive benchmark suite.
    
    Returns:
        Dictionary of benchmark categories and their test cases
    """
    return {
        "latency_tests": [
            create_performance_request(f"latency_{i}", "simple", 100)
            for i in range(100)
        ],
        "throughput_tests": [
            create_performance_request(f"throughput_{i}", "medium", 1000)
            for i in range(1000)
        ],
        "memory_tests": [
            create_performance_request(f"memory_{i}", "complex", 50000)
            for i in range(50)
        ],
        "cpu_tests": [
            create_performance_request(f"cpu_{i}", "complex", 1000)
            for i in range(500)
        ],
        "concurrent_tests": [
            create_performance_request(f"concurrent_{i}", "medium", 2000)
            for i in range(200)
        ]
    }


def generate_stress_test_requests(count: int = 10000) -> Generator[Dict[str, Any], None, None]:
    """Generate stress test requests as a generator to save memory.
    
    Args:
        count: Number of requests to generate
        
    Yields:
        Individual MCP requests
    """
    for i in range(count):
        yield create_performance_request(
            request_id=f"stress_{i}",
            complexity=random.choice(["simple", "medium", "complex"]),
            payload_size=random.randint(100, 100000)
        )


def create_security_performance_tests() -> List[Dict[str, Any]]:
    """Create performance tests that include security processing.
    
    Returns:
        List of requests that trigger security validation
    """
    requests = []
    
    # Requests that trigger input validation
    for i in range(100):
        request = {
            "jsonrpc": "2.0",
            "id": f"security_perf_{i}",
            "method": "tools/call",
            "params": {
                "command": fake.sentence(),
                "data": fake.text(max_nb_chars=5000),
                "nested": {
                    "level1": {
                        "level2": fake.text(max_nb_chars=1000)
                    }
                }
            }
        }
        requests.append(request)
    
    # Requests that trigger rate limiting
    for i in range(200):
        request = {
            "jsonrpc": "2.0",
            "id": f"rate_limit_perf_{i}",
            "method": "api/call",
            "params": {
                "rapid_fire": True,
                "timestamp": time.time() + (i * 0.01)  # Very close timestamps
            }
        }
        requests.append(request)
    
    # Requests that trigger AI immune system
    for i in range(50):
        request = {
            "jsonrpc": "2.0",
            "id": f"ai_immune_perf_{i}",
            "method": "tools/call",
            "params": {
                "unusual_pattern": "x" * random.randint(1000, 10000),
                "entropy_test": fake.random_letters(length=5000),
                "complexity": {
                    f"nested_{j}": fake.text(max_nb_chars=500)
                    for j in range(20)
                }
            }
        }
        requests.append(request)
    
    return requests


# Performance test configuration templates
PERFORMANCE_CONFIGS = {
    "minimal_overhead": {
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


def get_performance_scenario(name: str) -> PerformanceScenario:
    """Get a performance scenario by name.
    
    Args:
        name: Scenario name
        
    Returns:
        Performance scenario configuration
    """
    for scenario in PERFORMANCE_TEST_SCENARIOS:
        if scenario.name == name:
            return scenario
    
    raise ValueError(f"Unknown performance scenario: {name}")


def get_all_performance_scenarios() -> List[PerformanceScenario]:
    """Get all available performance scenarios.
    
    Returns:
        List of all performance scenarios
    """
    return PERFORMANCE_TEST_SCENARIOS.copy()
