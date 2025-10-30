"""Test suite for SMCP v1 Security Framework.

This package contains comprehensive tests for all security layers and components
of the Secure Model Context Protocol (SMCP) v1 framework.

Test Categories:
- Unit tests: Individual component testing
- Integration tests: Component interaction testing
- Security tests: Attack prevention and security control validation
- Performance tests: Benchmarking and performance validation
- End-to-end tests: Complete workflow testing

Test Structure:
- tests/unit/: Unit tests for each security layer
- tests/integration/: Integration tests for layer interactions
- tests/security/: Security-focused attack simulation tests
- tests/performance/: Performance benchmarks and load tests
- tests/e2e/: End-to-end workflow tests
- tests/fixtures/: Shared test fixtures and utilities
- tests/data/: Test data files and samples

Usage:
    # Run all tests
    pytest
    
    # Run specific test categories
    pytest -m unit
    pytest -m security
    pytest -m performance
    
    # Run with coverage
    pytest --cov=smcp_security
    
    # Run specific test files
    pytest tests/unit/test_input_validation.py
    pytest tests/security/test_attack_prevention.py
"""

__version__ = "1.0.0"
__author__ = "SMCP Security Team"
__email__ = "contact@example.org"
