#!/usr/bin/env python3
"""Test script to verify SMCP Security API deployment"""

import requests
import json
import sys
import time

def test_api(base_url="http://localhost:8080"):
    """Test all API endpoints"""
    print(f"Testing SMCP Security API at {base_url}")
    
    # Test 1: Health check
    print("\n1. Testing health endpoint...")
    try:
        response = requests.get(f"{base_url}/health")
        if response.status_code == 200:
            print("✅ Health check passed")
            print(f"   Status: {response.json()['status']}")
        else:
            print(f"❌ Health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Health check error: {e}")
        return False
    
    # Test 2: Root endpoint
    print("\n2. Testing root endpoint...")
    try:
        response = requests.get(f"{base_url}/")
        if response.status_code == 200:
            data = response.json()
            print("✅ Root endpoint passed")
            print(f"   Service: {data['service']}")
        else:
            print(f"❌ Root endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Root endpoint error: {e}")
    
    # Test 3: Demo endpoint
    print("\n3. Testing demo endpoint...")
    try:
        response = requests.get(f"{base_url}/demo")
        if response.status_code == 200:
            print("✅ Demo endpoint passed")
        else:
            print(f"❌ Demo endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Demo endpoint error: {e}")
    
    # Test 4: Validation endpoint (valid request)
    print("\n4. Testing validation with valid request...")
    try:
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer demo_key_123"
        }
        payload = {
            "request": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {}
            },
            "context": {
                "user_id": "test_user",
                "ip_address": "127.0.0.1"
            }
        }
        response = requests.post(f"{base_url}/validate", headers=headers, json=payload)
        if response.status_code == 200:
            data = response.json()
            if data['success']:
                print("✅ Valid request validation passed")
                print(f"   Security level: {data['security_metadata']['security_level']}")
            else:
                print(f"❌ Valid request rejected: {data['error']}")
        else:
            print(f"❌ Validation endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Validation endpoint error: {e}")
    
    # Test 5: Validation endpoint (malicious request)
    print("\n5. Testing validation with malicious request...")
    try:
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer demo_key_123"
        }
        payload = {
            "request": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "bash",
                    "arguments": {
                        "command": "rm -rf /"
                    }
                }
            },
            "context": {
                "user_id": "test_user",
                "ip_address": "127.0.0.1"
            }
        }
        response = requests.post(f"{base_url}/validate", headers=headers, json=payload)
        if response.status_code == 200:
            data = response.json()
            if not data['success'] and 'injection' in data['error'].lower():
                print("✅ Malicious request correctly blocked")
                print(f"   Error: {data['error'][:100]}...")
            else:
                print(f"❌ Malicious request not blocked properly")
        else:
            print(f"❌ Validation endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Malicious validation error: {e}")
    
    # Test 6: Metrics endpoint
    print("\n6. Testing metrics endpoint...")
    try:
        headers = {"Authorization": "Bearer demo_key_123"}
        response = requests.get(f"{base_url}/metrics", headers=headers)
        if response.status_code == 200:
            data = response.json()
            print("✅ Metrics endpoint passed")
            print(f"   Requests processed: {data['requests_processed']}")
            print(f"   Security score: {data['security_score']}")
        else:
            print(f"❌ Metrics endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Metrics endpoint error: {e}")
    
    # Test 7: Config endpoint
    print("\n7. Testing config endpoint...")
    try:
        headers = {"Authorization": "Bearer demo_key_123"}
        response = requests.get(f"{base_url}/config", headers=headers)
        if response.status_code == 200:
            data = response.json()
            print("✅ Config endpoint passed")
            print(f"   Validation strictness: {data['validation_strictness']}")
            print(f"   AI immune enabled: {data['enable_ai_immune']}")
        else:
            print(f"❌ Config endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Config endpoint error: {e}")
    
    print("\n🎉 API testing completed!")
    return True

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Test SMCP Security API")
    parser.add_argument("--url", default="http://localhost:8080", help="API base URL")
    args = parser.parse_args()
    
    success = test_api(args.url)
    sys.exit(0 if success else 1)
