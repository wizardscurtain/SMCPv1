"""Shared test fixtures and utilities for SMCP v1 tests.

This package contains reusable test fixtures, mock objects, and utility
functions used across different test categories.

Modules:
- attack_data: Malicious request patterns for security testing
- performance_data: Datasets for performance benchmarking
- mock_objects: Mock implementations for testing
- test_utils: Utility functions for test setup and validation
"""

from .attack_data import (
    COMMAND_INJECTION_PAYLOADS,
    SQL_INJECTION_PAYLOADS,
    XSS_PAYLOADS,
    PATH_TRAVERSAL_PAYLOADS,
    PROMPT_INJECTION_PAYLOADS,
    generate_malicious_request
)

from .performance_data import (
    PERFORMANCE_TEST_SCENARIOS,
    generate_performance_requests,
    create_load_test_data
)

from .mock_objects import (
    MockMLModel,
    MockCryptoProvider,
    MockNetworkService,
    MockDatabase
)

from .test_utils import (
    assert_security_violation,
    measure_execution_time,
    create_test_user,
    generate_test_token,
    validate_audit_log
)

__all__ = [
    # Attack data
    "COMMAND_INJECTION_PAYLOADS",
    "SQL_INJECTION_PAYLOADS", 
    "XSS_PAYLOADS",
    "PATH_TRAVERSAL_PAYLOADS",
    "PROMPT_INJECTION_PAYLOADS",
    "generate_malicious_request",
    
    # Performance data
    "PERFORMANCE_TEST_SCENARIOS",
    "generate_performance_requests",
    "create_load_test_data",
    
    # Mock objects
    "MockMLModel",
    "MockCryptoProvider",
    "MockNetworkService",
    "MockDatabase",
    
    # Test utilities
    "assert_security_violation",
    "measure_execution_time",
    "create_test_user",
    "generate_test_token",
    "validate_audit_log"
]
