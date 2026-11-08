"""Prebug v0.2-derived stateful SMCP security regression probes.
Deliberately policy-bearing tests. No third-party network or live endpoints.
"""
import pytest
from smcp_security.authorization import RBACManager, Role, Permission, AuthorizationContext
from smcp_security.core import SecurityConfig, SMCPSecurityFramework
from smcp_security.exceptions import AuthorizationError

def framework(**options):
    base = dict(enable_input_validation=False, enable_mfa=False, enable_rbac=False,
                enable_rate_limiting=False, enable_encryption=False,
                enable_ai_immune=False, enable_audit_logging=False)
    base.update(options)
    return SMCPSecurityFramework(SecurityConfig(**base))

def mcp(method='tools/list', params=None):
    return {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or {}}

def test_resource_scope_and_revocation_lifecycle():
    auth = RBACManager()
    auth.define_role('scoped-reader', ['mcp:read:files'])
    auth.assign_role('demo', 'scoped-reader')
    assert auth.check_permission('demo', 'mcp:read', 'files')
    assert not auth.check_permission('demo', 'mcp:read', 'database')
    auth.revoke_role('demo', 'scoped-reader')
    assert not auth.check_permission('demo', 'mcp:read', 'files')

def test_context_changes_do_not_use_stale_auth_cache():
    auth = RBACManager()
    auth.roles['timed'] = Role(name='timed', permissions=[
        Permission(action='mcp:read', conditions={'time_range': {'start': 9, 'end': 17}})])
    auth.assign_role('demo', 'timed')
    assert auth.check_permission('demo', 'mcp:read',
        context=AuthorizationContext(user_id='demo', time_of_day=14))
    assert not auth.check_permission('demo', 'mcp:read',
        context=AuthorizationContext(user_id='demo', time_of_day=20))
    assert auth.check_permission('demo', 'mcp:read',
        context=AuthorizationContext(user_id='demo', time_of_day=14))

def test_missing_conditional_context_must_fail_closed():
    auth = RBACManager()
    auth.roles['timed'] = Role(name='timed', permissions=[
        Permission(action='mcp:read', conditions={'time_range': {'start': 9, 'end': 17}})])
    auth.assign_role('demo', 'timed')
    assert not auth.check_permission('demo', 'mcp:read', context=None)

@pytest.mark.asyncio
async def test_revoked_role_not_reinstalled_by_token_on_next_request():
    fw = framework(enable_rbac=True)
    fw.rbac_manager.define_role('prebug-reader', ['mcp:read'])
    token = fw.jwt_auth.generate_token('demo', roles=['prebug-reader'], mfa_verified=True)
    ctx = {'token': token}
    assert (await fw.process_request(mcp(), ctx))['request']['method'] == 'tools/list'
    fw.rbac_manager.revoke_role('demo', 'prebug-reader')
    with pytest.raises(AuthorizationError):
        await fw.process_request(mcp(), ctx)

@pytest.mark.asyncio
async def test_encryption_failure_cannot_succeed_in_plaintext():
    fw = framework(enable_encryption=True)
    token = fw.jwt_auth.generate_token('demo', mfa_verified=True)
    def fail(*args, **kwargs):
        raise RuntimeError('PREBUG_INJECTED_CRYPTO_FAILURE')
    fw.crypto_manager.analyze_request = fail
    with pytest.raises(RuntimeError, match='PREBUG_INJECTED_CRYPTO_FAILURE'):
        await fw.process_request(mcp(params={'data': 'synthetic'}), {
            'token': token, 'encrypt_payload': True})

@pytest.mark.asyncio
async def test_encryption_metadata_reports_actual_behavior():
    fw = framework(enable_encryption=True)
    token = fw.jwt_auth.generate_token('demo', mfa_verified=True)
    out = await fw.process_request(mcp(params={'data': 'synthetic'}), {
        'token': token, 'encrypt_payload': False})
    assert out['security_metadata']['encryption_applied'] is False
    assert '_encrypted_params' not in out['request']

@pytest.mark.asyncio
async def test_hosted_api_context_works_with_security_framework():
    fw = framework()
    ctx = {'api_user': 'Demo User', 'api_tier': 'free', 'user_id': 'Demo User'}
    out = await fw.process_request(mcp(), ctx)
    assert out['request']['method'] == 'tools/list'

@pytest.mark.xfail(strict=True, reason='Candidate policy: unknown methods must deny')
def test_unknown_method_no_generic_read_grant():
    fw = framework()
    assert fw._determine_required_permission(mcp('unrecognized/operation')) == 'DENY'

@pytest.mark.xfail(strict=True, reason='Candidate policy: named tool calls need capability-specific authorization')
def test_named_tool_invocation_not_same_as_list():
    fw = framework()
    assert fw._determine_required_permission(mcp('tools/call', {'name': 'delete-repository'})) != 'mcp:read'
