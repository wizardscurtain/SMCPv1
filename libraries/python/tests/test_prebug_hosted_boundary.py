"""Prebug security boundary probes for hosted SMCP API.
Local ASGI tests only; no live endpoints or production credentials used.
"""
import importlib.util
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from smcp_security.core import SecurityConfig, SMCPSecurityFramework

@pytest.fixture
def hosted(monkeypatch):
    monkeypatch.setenv('SMCP_MASTER_KEY', 'prebug-test-key-not-for-deployment')
    root = Path(__file__).resolve().parents[3]
    path = root / 'deployment' / 'hosted-api' / 'app.py'
    spec = importlib.util.spec_from_file_location('prebug_hosted_under_test', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.security_framework = SMCPSecurityFramework(SecurityConfig(
        enable_input_validation=False, enable_mfa=False, enable_rbac=False,
        enable_rate_limiting=False, enable_encryption=False,
        enable_ai_immune=False, enable_audit_logging=False,
    ))
    return mod, TestClient(mod.app)

def payload(**kw):
    return {'request': {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list', 'params': {}},
            'context': {}, **kw}

def test_hosted_rejects_missing_and_invalid_keys(hosted):
    _, client = hosted
    assert client.post('/validate', json=payload()).status_code == 401
    assert client.post('/validate', json=payload(), headers={
        'Authorization': 'Bearer invalid-key'}).status_code == 401
    assert client.post('/validate', json=payload(), headers={
        'Authorization': 'Bearer demo_key_123'}).status_code == 401

def test_hosted_valid_key_bridges_identity_not_caller_context(hosted):
    _, client = hosted
    body = payload()
    body['context'] = {'user_id': 'injected-admin', 'token': 'fake',
                       'roles': ['admin'], 'permissions': ['system:*']}
    r = client.post('/validate', json=body, headers={
        'Authorization': 'Bearer prebug-test-key-not-for-deployment'})
    assert r.status_code == 200
    data = r.json()
    assert data['success'] is True, data
    assert data['context']['user_id'] == 'Master'
    assert 'admin' not in data['context'].get('roles', [])

def test_hosted_rejects_policy_override(hosted):
    _, client = hosted
    r = client.post('/validate', json=payload(config={'enable_rbac': False}),
        headers={'Authorization': 'Bearer prebug-test-key-not-for-deployment'})
    assert r.status_code == 200
    data = r.json()
    assert data['success'] is False
    assert data['error_code'] == 'AUTHORIZATION_ERROR'

def test_hosted_does_not_leak_credentials_in_demo(hosted):
    _, client = hosted
    demo = client.get('/demo').json()
    assert 'api_keys' not in demo
    assert 'demo_key_123' not in str(demo)
