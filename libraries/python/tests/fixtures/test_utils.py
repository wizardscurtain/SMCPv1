"""Utility functions for SMCP v1 testing.

This module provides helper functions for test setup, validation,
and common testing operations.
"""

import time
import json
import hashlib
import secrets
from typing import Dict, Any, List, Optional, Callable, Union
from datetime import datetime, timedelta
from contextlib import contextmanager
from unittest.mock import patch
import functools

# Import SMCP components
from smcp_security.exceptions import SecurityError, ValidationError, AuthenticationError
from smcp_security.audit import SMCPAuditLogger, EventSeverity, EventCategory


def assert_security_violation(func: Callable, *args, **kwargs) -> bool:
    """Assert that a function raises a security-related exception.
    
    Args:
        func: Function to test
        *args: Function arguments
        **kwargs: Function keyword arguments
        
    Returns:
        True if security exception was raised, False otherwise
    """
    try:
        func(*args, **kwargs)
        return False
    except (SecurityError, ValidationError, AuthenticationError):
        return True
    except Exception:
        return False


def measure_execution_time(func: Callable, *args, **kwargs) -> Dict[str, Any]:
    """Measure function execution time and memory usage.
    
    Args:
        func: Function to measure
        *args: Function arguments
        **kwargs: Function keyword arguments
        
    Returns:
        Dictionary with timing and memory information
    """
    import tracemalloc
    import psutil
    import os
    
    # Get initial memory usage
    process = psutil.Process(os.getpid())
    initial_memory = process.memory_info().rss
    
    # Start memory tracking
    tracemalloc.start()
    
    # Measure execution time
    start_time = time.perf_counter()
    start_cpu_time = time.process_time()
    
    try:
        result = func(*args, **kwargs)
        success = True
        error = None
    except Exception as e:
        result = None
        success = False
        error = str(e)
    
    end_time = time.perf_counter()
    end_cpu_time = time.process_time()
    
    # Get memory usage
    current_memory, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    final_memory = process.memory_info().rss
    
    return {
        "result": result,
        "success": success,
        "error": error,
        "wall_time": end_time - start_time,
        "cpu_time": end_cpu_time - start_cpu_time,
        "memory_current": current_memory,
        "memory_peak": peak_memory,
        "memory_delta": final_memory - initial_memory,
        "memory_initial": initial_memory,
        "memory_final": final_memory
    }


def create_test_user(user_id: str = None, 
                    roles: List[str] = None,
                    permissions: List[str] = None,
                    email: str = None) -> Dict[str, Any]:
    """Create a test user with specified attributes.
    
    Args:
        user_id: User identifier
        roles: List of user roles
        permissions: List of user permissions
        email: User email address
        
    Returns:
        Test user dictionary
    """
    if user_id is None:
        user_id = f"test_user_{secrets.token_hex(4)}"
    
    if roles is None:
        roles = ["user"]
    
    if permissions is None:
        permissions = ["mcp:read"]
    
    if email is None:
        email = f"{user_id}@example.com"
    
    return {
        "user_id": user_id,
        "email": email,
        "roles": roles,
        "permissions": permissions,
        "created_at": datetime.utcnow(),
        "is_active": True,
        "metadata": {
            "last_login": datetime.utcnow() - timedelta(hours=1),
            "login_count": 10,
            "failed_attempts": 0
        }
    }


def generate_test_token(jwt_authenticator, 
                       user_id: str = "test_user",
                       roles: List[str] = None,
                       permissions: List[str] = None,
                       mfa_verified: bool = True,
                       expired: bool = False) -> str:
    """Generate a test JWT token.
    
    Args:
        jwt_authenticator: JWT authenticator instance
        user_id: User identifier
        roles: User roles
        permissions: User permissions
        mfa_verified: Whether MFA is verified
        expired: Whether to create an expired token
        
    Returns:
        JWT token string
    """
    if roles is None:
        roles = ["user"]
    
    if permissions is None:
        permissions = ["mcp:read"]
    
    token = jwt_authenticator.generate_token(
        user_id=user_id,
        roles=roles,
        permissions=permissions,
        mfa_verified=mfa_verified
    )
    
    if expired:
        # Create an expired token by manipulating the expiry time
        # This is a simplified approach for testing
        import jwt
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            payload['exp'] = int(time.time()) - 3600  # Expired 1 hour ago
            token = jwt.encode(payload, jwt_authenticator.config.jwt_secret_key, 
                             algorithm=jwt_authenticator.config.jwt_algorithm)
        except Exception:
            pass  # Return original token if manipulation fails
    
    return token


def validate_audit_log(audit_logger: SMCPAuditLogger,
                      expected_events: List[Dict[str, Any]],
                      exact_match: bool = False) -> bool:
    """Validate that expected events are present in audit log.
    
    Args:
        audit_logger: Audit logger instance
        expected_events: List of expected event patterns
        exact_match: Whether to require exact matches
        
    Returns:
        True if all expected events are found
    """
    actual_events = audit_logger.get_events(limit=1000)
    
    for expected in expected_events:
        found = False
        
        for actual in actual_events:
            if exact_match:
                # Exact match comparison
                match = all(
                    actual.get(key) == value 
                    for key, value in expected.items()
                )
            else:
                # Partial match comparison
                match = all(
                    key in actual and actual[key] == value
                    for key, value in expected.items()
                )
            
            if match:
                found = True
                break
        
        if not found:
            return False
    
    return True


def create_test_mcp_request(method: str = "tools/list",
                           params: Dict[str, Any] = None,
                           request_id: str = None) -> Dict[str, Any]:
    """Create a test MCP request.
    
    Args:
        method: MCP method name
        params: Request parameters
        request_id: Request identifier
        
    Returns:
        MCP request dictionary
    """
    if params is None:
        params = {}
    
    if request_id is None:
        request_id = f"test_req_{secrets.token_hex(4)}"
    
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": params
    }


def create_malicious_mcp_request(attack_type: str,
                                payload: str = None) -> Dict[str, Any]:
    """Create a malicious MCP request for testing.
    
    Args:
        attack_type: Type of attack to simulate
        payload: Custom payload (optional)
        
    Returns:
        Malicious MCP request
    """
    from .attack_data import generate_malicious_request
    
    if payload:
        # Custom payload
        request = create_test_mcp_request()
        request["params"]["malicious_data"] = payload
        return request
    else:
        # Use predefined attack patterns
        return generate_malicious_request(attack_type)


def simulate_concurrent_requests(func: Callable,
                               requests: List[Any],
                               max_workers: int = 10) -> List[Dict[str, Any]]:
    """Simulate concurrent request processing.
    
    Args:
        func: Function to process requests
        requests: List of requests to process
        max_workers: Maximum number of concurrent workers
        
    Returns:
        List of processing results
    """
    import concurrent.futures
    import threading
    
    results = []
    lock = threading.Lock()
    
    def process_request(request):
        start_time = time.time()
        try:
            result = func(request)
            success = True
            error = None
        except Exception as e:
            result = None
            success = False
            error = str(e)
        
        end_time = time.time()
        
        with lock:
            results.append({
                "request": request,
                "result": result,
                "success": success,
                "error": error,
                "processing_time": end_time - start_time,
                "thread_id": threading.current_thread().ident
            })
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(process_request, req) for req in requests]
        concurrent.futures.wait(futures)
    
    return results


def benchmark_function(func: Callable,
                      iterations: int = 1000,
                      warmup_iterations: int = 100) -> Dict[str, float]:
    """Benchmark a function's performance.
    
    Args:
        func: Function to benchmark
        iterations: Number of benchmark iterations
        warmup_iterations: Number of warmup iterations
        
    Returns:
        Benchmark statistics
    """
    import statistics
    
    # Warmup
    for _ in range(warmup_iterations):
        try:
            func()
        except Exception:
            pass
    
    # Benchmark
    times = []
    for _ in range(iterations):
        start_time = time.perf_counter()
        try:
            func()
            success = True
        except Exception:
            success = False
        end_time = time.perf_counter()
        
        if success:
            times.append(end_time - start_time)
    
    if not times:
        return {
            "min": 0, "max": 0, "mean": 0, "median": 0,
            "std_dev": 0, "success_rate": 0, "iterations": 0
        }
    
    return {
        "min": min(times),
        "max": max(times),
        "mean": statistics.mean(times),
        "median": statistics.median(times),
        "std_dev": statistics.stdev(times) if len(times) > 1 else 0,
        "p95": statistics.quantiles(times, n=20)[18] if len(times) >= 20 else max(times),
        "p99": statistics.quantiles(times, n=100)[98] if len(times) >= 100 else max(times),
        "success_rate": len(times) / iterations,
        "iterations": len(times)
    }


@contextmanager
def temporary_config(obj, **config_changes):
    """Temporarily change object configuration for testing.
    
    Args:
        obj: Object to modify
        **config_changes: Configuration changes to apply
    """
    original_values = {}
    
    # Store original values and apply changes
    for key, value in config_changes.items():
        if hasattr(obj, key):
            original_values[key] = getattr(obj, key)
            setattr(obj, key, value)
    
    try:
        yield obj
    finally:
        # Restore original values
        for key, value in original_values.items():
            setattr(obj, key, value)


def create_performance_monitor():
    """Create a performance monitoring context manager.
    
    Returns:
        Performance monitor context manager
    """
    class PerformanceMonitor:
        def __init__(self):
            self.start_time = None
            self.end_time = None
            self.memory_start = None
            self.memory_end = None
            self.cpu_start = None
            self.cpu_end = None
        
        def __enter__(self):
            import psutil
            import os
            
            process = psutil.Process(os.getpid())
            
            self.start_time = time.perf_counter()
            self.cpu_start = time.process_time()
            self.memory_start = process.memory_info().rss
            
            return self
        
        def __exit__(self, exc_type, exc_val, exc_tb):
            import psutil
            import os
            
            process = psutil.Process(os.getpid())
            
            self.end_time = time.perf_counter()
            self.cpu_end = time.process_time()
            self.memory_end = process.memory_info().rss
        
        @property
        def wall_time(self):
            return self.end_time - self.start_time if self.end_time else 0
        
        @property
        def cpu_time(self):
            return self.cpu_end - self.cpu_start if self.cpu_end else 0
        
        @property
        def memory_delta(self):
            return self.memory_end - self.memory_start if self.memory_end else 0
        
        def get_stats(self):
            return {
                "wall_time": self.wall_time,
                "cpu_time": self.cpu_time,
                "memory_delta": self.memory_delta,
                "memory_start": self.memory_start,
                "memory_end": self.memory_end
            }
    
    return PerformanceMonitor()


def generate_test_data(data_type: str, count: int = 10) -> List[Any]:
    """Generate test data of specified type.
    
    Args:
        data_type: Type of data to generate
        count: Number of items to generate
        
    Returns:
        List of generated test data
    """
    from faker import Faker
    fake = Faker()
    
    generators = {
        "users": lambda: create_test_user(),
        "requests": lambda: create_test_mcp_request(),
        "emails": lambda: fake.email(),
        "names": lambda: fake.name(),
        "addresses": lambda: fake.address(),
        "phone_numbers": lambda: fake.phone_number(),
        "urls": lambda: fake.url(),
        "text": lambda: fake.text(),
        "sentences": lambda: fake.sentence(),
        "words": lambda: fake.word(),
        "numbers": lambda: fake.random_number(digits=5),
        "dates": lambda: fake.date_time(),
        "uuids": lambda: fake.uuid4(),
        "ip_addresses": lambda: fake.ipv4(),
        "user_agents": lambda: fake.user_agent()
    }
    
    if data_type not in generators:
        raise ValueError(f"Unknown data type: {data_type}")
    
    return [generators[data_type]() for _ in range(count)]


def assert_performance_within_limits(execution_time: float,
                                   max_time: float,
                                   memory_usage: int = None,
                                   max_memory: int = None) -> bool:
    """Assert that performance is within acceptable limits.
    
    Args:
        execution_time: Actual execution time
        max_time: Maximum allowed execution time
        memory_usage: Actual memory usage (optional)
        max_memory: Maximum allowed memory usage (optional)
        
    Returns:
        True if within limits, False otherwise
    """
    time_ok = execution_time <= max_time
    
    if memory_usage is not None and max_memory is not None:
        memory_ok = memory_usage <= max_memory
        return time_ok and memory_ok
    
    return time_ok


def create_test_environment() -> Dict[str, Any]:
    """Create a complete test environment with all necessary components.
    
    Returns:
        Dictionary containing test environment components
    """
    from .mock_objects import (
        MockDatabase, MockNetworkService, MockFileSystem,
        MockRedisCache, MockMetrics
    )
    
    return {
        "database": MockDatabase(),
        "network": MockNetworkService(),
        "filesystem": MockFileSystem(),
        "cache": MockRedisCache(),
        "metrics": MockMetrics(),
        "start_time": time.time()
    }


def cleanup_test_environment(env: Dict[str, Any]):
    """Clean up test environment resources.
    
    Args:
        env: Test environment dictionary
    """
    # Disconnect database
    if "database" in env and hasattr(env["database"], "disconnect"):
        env["database"].disconnect()
    
    # Clear caches
    if "cache" in env and hasattr(env["cache"], "flushall"):
        env["cache"].flushall()
    
    # Clear logs
    for component in env.values():
        if hasattr(component, "clear_log"):
            component.clear_log()


def retry_on_failure(max_attempts: int = 3, delay: float = 0.1):
    """Decorator to retry function on failure.
    
    Args:
        max_attempts: Maximum number of retry attempts
        delay: Delay between attempts in seconds
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_attempts - 1:
                        time.sleep(delay)
                    continue
            
            raise last_exception
        
        return wrapper
    return decorator


def timeout_after(seconds: float):
    """Decorator to timeout function after specified seconds.
    
    Args:
        seconds: Timeout in seconds
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            import signal
            
            def timeout_handler(signum, frame):
                raise TimeoutError(f"Function timed out after {seconds} seconds")
            
            # Set timeout
            old_handler = signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(int(seconds))
            
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                # Clear timeout
                signal.alarm(0)
                signal.signal(signal.SIGALRM, old_handler)
        
        return wrapper
    return decorator


def hash_request(request: Dict[str, Any]) -> str:
    """Create a hash of an MCP request for comparison.
    
    Args:
        request: MCP request dictionary
        
    Returns:
        SHA256 hash of the request
    """
    request_str = json.dumps(request, sort_keys=True)
    return hashlib.sha256(request_str.encode()).hexdigest()


def compare_requests(req1: Dict[str, Any], req2: Dict[str, Any]) -> bool:
    """Compare two MCP requests for equality.
    
    Args:
        req1: First request
        req2: Second request
        
    Returns:
        True if requests are equal
    """
    return hash_request(req1) == hash_request(req2)


def extract_security_metadata(response: Dict[str, Any]) -> Dict[str, Any]:
    """Extract security metadata from a response.
    
    Args:
        response: Response dictionary
        
    Returns:
        Security metadata dictionary
    """
    return response.get("security_metadata", {})


def validate_response_structure(response: Dict[str, Any],
                              required_fields: List[str] = None) -> bool:
    """Validate response structure.
    
    Args:
        response: Response to validate
        required_fields: List of required fields
        
    Returns:
        True if structure is valid
    """
    if required_fields is None:
        required_fields = ["request", "context"]
    
    return all(field in response for field in required_fields)
