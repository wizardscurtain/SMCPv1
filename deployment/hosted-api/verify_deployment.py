#!/usr/bin/env python3
"""Deployment verification script for SMCP Security API on Render"""

import sys
import os
import importlib.util

def verify_module_imports():
    """Verify that all required modules can be imported"""
    print("🔍 Verifying module imports...")
    
    try:
        # Test SMCP security imports
        from smcp_security import SMCPSecurityFramework, SecurityConfig
        from smcp_security.exceptions import (
            SecurityError, ValidationError, AuthenticationError,
            AuthorizationError, RateLimitError
        )
        print("✅ SMCP security modules imported successfully")
        
        # Test FastAPI imports
        from fastapi import FastAPI
        import uvicorn
        print("✅ FastAPI modules imported successfully")
        
        # Test other dependencies
        import jsonschema
        import cryptography
        import jwt
        print("✅ All dependencies imported successfully")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False

def verify_security_framework():
    """Verify that the security framework can be initialized"""
    print("\n🔍 Verifying security framework initialization...")
    
    try:
        from smcp_security import SMCPSecurityFramework, SecurityConfig
        
        config = SecurityConfig(
            enable_input_validation=True,
            validation_strictness="standard",
            enable_mfa=False,
            enable_rbac=False,
            enable_rate_limiting=False,
            enable_encryption=True,
            enable_ai_immune=True,
            anomaly_threshold=0.7,
            enable_audit_logging=True,
            log_level="INFO"
        )
        
        framework = SMCPSecurityFramework(config)
        print("✅ Security framework initialized successfully")
        
        # Test processing a simple request
        import asyncio
        
        test_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }
        
        test_context = {
            "user_id": "test_user",
            "api_user": "Test User",
            "api_tier": "demo",
            "client_ip": "127.0.0.1"
        }
        
        result = asyncio.run(framework.process_request(test_request, test_context))
        print("✅ Security framework processing test passed")
        print(f"   Security level: {result['security_metadata']['security_level']}")
        
        return True
        
    except Exception as e:
        print(f"❌ Security framework error: {e}")
        import traceback
        traceback.print_exc()
        return False

def verify_app_startup():
    """Verify that the app can start up without errors"""
    print("\n🔍 Verifying app startup...")
    
    try:
        # Import the app module
        sys.path.insert(0, os.path.dirname(__file__))
        
        # Test the path resolution logic
        current_dir = os.path.dirname(os.path.abspath(__file__))
        possible_paths = [
            '/opt/render/project/src/code',
            '/app/code',
            os.path.join(current_dir, '../../code'),
            os.path.join(current_dir, 'smcp_security'),
            './smcp_security'
        ]
        
        smcp_path = None
        for path in possible_paths:
            if os.path.exists(os.path.join(path, 'smcp_security')) or os.path.exists(path):
                smcp_path = path
                break
        
        if smcp_path:
            print(f"✅ Found SMCP module at: {smcp_path}")
        else:
            print("❌ Could not find SMCP module")
            return False
        
        # Test importing the app
        import app
        print("✅ App module imported successfully")
        
        # Test FastAPI app creation
        if hasattr(app, 'app') and app.app:
            print("✅ FastAPI app created successfully")
        else:
            print("❌ FastAPI app not found")
            return False
        
        return True
        
    except Exception as e:
        print(f"❌ App startup error: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all verification tests"""
    print("🚀 SMCP Security API Deployment Verification")
    print("=" * 50)
    
    # Check Python version
    print(f"Python version: {sys.version}")
    print(f"Current directory: {os.getcwd()}")
    
    # Run verification tests
    tests = [
        verify_module_imports,
        verify_security_framework,
        verify_app_startup
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        else:
            print(f"\n❌ Test failed: {test.__name__}")
    
    print("\n" + "=" * 50)
    print(f"📊 Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All verification tests passed! Deployment is ready.")
        return True
    else:
        print("💥 Some tests failed. Please check the errors above.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
