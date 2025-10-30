"""Unit tests for authorization and RBAC mechanisms.

Tests the RBACManager and authorization components.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

from smcp_security.authorization import (
    RBACManager, Permission, Role, AuthorizationContext, PermissionEffect
)
from smcp_security.exceptions import AuthorizationError


class TestPermission:
    """Test Permission data class."""
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_permission_creation(self):
        """Test permission creation with defaults."""
        permission = Permission(action="mcp:read")
        
        assert permission.action == "mcp:read"
        assert permission.resource == "*"
        assert permission.effect == PermissionEffect.ALLOW
        assert isinstance(permission.conditions, dict)
        assert isinstance(permission.created_at, datetime)
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_permission_with_custom_values(self):
        """Test permission creation with custom values."""
        conditions = {"time_range": {"start": 9, "end": 17}}
        
        permission = Permission(
            action="mcp:write",
            resource="files:/home/*",
            effect=PermissionEffect.DENY,
            conditions=conditions
        )
        
        assert permission.action == "mcp:write"
        assert permission.resource == "files:/home/*"
        assert permission.effect == PermissionEffect.DENY
        assert permission.conditions == conditions


class TestRole:
    """Test Role data class."""
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_role_creation(self):
        """Test role creation with defaults."""
        role = Role(name="test_role")
        
        assert role.name == "test_role"
        assert isinstance(role.permissions, list)
        assert len(role.permissions) == 0
        assert role.description == ""
        assert role.is_active is True
        assert isinstance(role.parent_roles, list)
        assert isinstance(role.created_at, datetime)
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_role_with_permissions(self):
        """Test role creation with permissions."""
        permissions = [
            Permission(action="mcp:read"),
            Permission(action="mcp:write", resource="files:*")
        ]
        
        role = Role(
            name="power_user",
            permissions=permissions,
            description="Power user role",
            parent_roles=["user"]
        )
        
        assert role.name == "power_user"
        assert len(role.permissions) == 2
        assert role.description == "Power user role"
        assert role.parent_roles == ["user"]


class TestAuthorizationContext:
    """Test AuthorizationContext data class."""
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_context_creation(self):
        """Test authorization context creation."""
        context = AuthorizationContext(
            user_id="test_user",
            ip_address="192.168.1.100",
            time_of_day=14,
            day_of_week=1
        )
        
        assert context.user_id == "test_user"
        assert context.ip_address == "192.168.1.100"
        assert context.time_of_day == 14
        assert context.day_of_week == 1
        assert isinstance(context.resource_attributes, dict)
        assert isinstance(context.session_attributes, dict)


class TestRBACManager:
    """Test RBAC manager functionality."""
    
    @pytest.fixture
    def rbac_manager(self):
        return RBACManager()
    
    @pytest.fixture
    def populated_rbac_manager(self):
        """RBAC manager with predefined roles and users."""
        manager = RBACManager()
        
        # Define roles
        manager.define_role("guest", ["mcp:read:public"])
        manager.define_role("user", ["mcp:read", "mcp:execute:safe_tools"])
        manager.define_role("admin", ["mcp:*", "system:*"])
        
        # Assign users
        manager.assign_role("guest_user", "guest")
        manager.assign_role("regular_user", "user")
        manager.assign_role("admin_user", "admin")
        
        return manager
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_role_definition(self, rbac_manager):
        """Test role definition functionality."""
        permissions = ["mcp:read", "mcp:write"]
        
        role = rbac_manager.define_role(
            "test_role",
            permissions=permissions,
            description="Test role"
        )
        
        assert role.name == "test_role"
        assert len(role.permissions) == 2
        assert role.description == "Test role"
        
        # Role should be stored
        assert "test_role" in rbac_manager.roles
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_permission_string_parsing(self, rbac_manager):
        """Test parsing of permission strings."""
        test_cases = [
            ("mcp:read", "mcp:read", "*", PermissionEffect.ALLOW),
            ("allow:mcp:write", "mcp:write", "*", PermissionEffect.ALLOW),
            ("deny:mcp:delete", "mcp:delete", "*", PermissionEffect.DENY),
            ("mcp:read:files", "mcp:read", "files", PermissionEffect.ALLOW),
            ("deny:mcp:write:sensitive", "mcp:write", "sensitive", PermissionEffect.DENY)
        ]
        
        for perm_str, expected_action, expected_resource, expected_effect in test_cases:
            permission = rbac_manager._parse_permission_string(perm_str)
            
            assert permission.action == expected_action
            assert permission.resource == expected_resource
            assert permission.effect == expected_effect
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_role_assignment(self, rbac_manager):
        """Test role assignment to users."""
        # Define role first
        rbac_manager.define_role("test_role", ["mcp:read"])
        
        # Assign role to user
        rbac_manager.assign_role("test_user", "test_role")
        
        # User should have the role
        user_roles = rbac_manager.get_user_roles("test_user")
        assert "test_role" in user_roles
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_role_assignment_nonexistent_role(self, rbac_manager):
        """Test assignment of non-existent role raises error."""
        with pytest.raises(AuthorizationError, match="Role 'nonexistent' does not exist"):
            rbac_manager.assign_role("test_user", "nonexistent")
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_role_revocation(self, rbac_manager):
        """Test role revocation from users."""
        # Setup
        rbac_manager.define_role("test_role", ["mcp:read"])
        rbac_manager.assign_role("test_user", "test_role")
        
        # Verify role is assigned
        assert "test_role" in rbac_manager.get_user_roles("test_user")
        
        # Revoke role
        rbac_manager.revoke_role("test_user", "test_role")
        
        # Role should be removed
        assert "test_role" not in rbac_manager.get_user_roles("test_user")
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_permission_checking_allow(self, populated_rbac_manager):
        """Test permission checking with allow permissions."""
        # Regular user should have read permission
        result = populated_rbac_manager.check_permission(
            "regular_user", "mcp:read"
        )
        assert result is True
        
        # Admin should have all permissions
        result = populated_rbac_manager.check_permission(
            "admin_user", "mcp:write"
        )
        assert result is True
        
        result = populated_rbac_manager.check_permission(
            "admin_user", "system:config"
        )
        assert result is True
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_permission_checking_deny(self, populated_rbac_manager):
        """Test permission checking with deny permissions."""
        # Guest should not have write permission
        result = populated_rbac_manager.check_permission(
            "guest_user", "mcp:write"
        )
        assert result is False
        
        # Regular user should not have admin permissions
        result = populated_rbac_manager.check_permission(
            "regular_user", "system:config"
        )
        assert result is False
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_wildcard_permissions(self, rbac_manager):
        """Test wildcard permission matching."""
        # Define role with wildcard permission
        rbac_manager.define_role("wildcard_role", ["mcp:*"])
        rbac_manager.assign_role("wildcard_user", "wildcard_role")
        
        # Should match any mcp action
        test_permissions = [
            "mcp:read", "mcp:write", "mcp:delete", "mcp:execute"
        ]
        
        for permission in test_permissions:
            result = rbac_manager.check_permission("wildcard_user", permission)
            assert result is True
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_resource_specific_permissions(self, rbac_manager):
        """Test resource-specific permission checking."""
        # Define role with resource-specific permissions
        rbac_manager.define_role("file_user", ["mcp:read:files", "mcp:write:files"])
        rbac_manager.assign_role("file_user_id", "file_user")
        
        # Should have permission for files resource
        result = rbac_manager.check_permission(
            "file_user_id", "mcp:read", "files"
        )
        assert result is True
        
        # Should not have permission for other resources
        result = rbac_manager.check_permission(
            "file_user_id", "mcp:read", "database"
        )
        assert result is False
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_deny_takes_precedence(self, rbac_manager):
        """Test that deny permissions take precedence over allow."""
        # Define role with both allow and deny for same action
        rbac_manager.define_role("mixed_role", [
            "allow:mcp:read",
            "deny:mcp:read:sensitive"
        ])
        rbac_manager.assign_role("mixed_user", "mixed_role")
        
        # Should have general read permission
        result = rbac_manager.check_permission("mixed_user", "mcp:read")
        assert result is True
        
        # Should be denied for sensitive resource
        result = rbac_manager.check_permission(
            "mixed_user", "mcp:read", "sensitive"
        )
        assert result is False
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_role_inheritance(self, rbac_manager):
        """Test role inheritance functionality."""
        # Define parent role
        rbac_manager.define_role("base_user", ["mcp:read"])
        
        # Define child role that inherits from parent
        rbac_manager.define_role(
            "extended_user", 
            ["mcp:write"], 
            parent_roles=["base_user"]
        )
        
        rbac_manager.assign_role("inherited_user", "extended_user")
        
        # Should have permissions from both roles
        assert rbac_manager.check_permission("inherited_user", "mcp:read")  # From parent
        assert rbac_manager.check_permission("inherited_user", "mcp:write")  # From child
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_conditional_permissions(self, rbac_manager):
        """Test conditional permission evaluation."""
        # This test requires manual permission creation with conditions
        time_restricted_permission = Permission(
            action="mcp:admin",
            conditions={"time_range": {"start": 9, "end": 17}}
        )
        
        role = Role(name="time_restricted", permissions=[time_restricted_permission])
        rbac_manager.roles["time_restricted"] = role
        rbac_manager.assign_role("time_user", "time_restricted")
        
        # Create contexts for different times
        work_hours_context = AuthorizationContext(
            user_id="time_user",
            time_of_day=14  # 2 PM
        )
        
        after_hours_context = AuthorizationContext(
            user_id="time_user",
            time_of_day=20  # 8 PM
        )
        
        # Should be allowed during work hours
        result = rbac_manager.check_permission(
            "time_user", "mcp:admin", context=work_hours_context
        )
        assert result is True
        
        # Should be denied after hours
        result = rbac_manager.check_permission(
            "time_user", "mcp:admin", context=after_hours_context
        )
        assert result is False
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_permission_caching(self, rbac_manager):
        """Test permission result caching."""
        # Define role and user
        rbac_manager.define_role("cached_role", ["mcp:read"])
        rbac_manager.assign_role("cached_user", "cached_role")
        
        # First check should compute result
        result1 = rbac_manager.check_permission("cached_user", "mcp:read")
        assert result1 is True
        
        # Second check should use cache (verify by checking cache exists)
        cache_key = "cached_user:mcp:read:*"
        assert "cached_user" in rbac_manager.permission_cache
        
        result2 = rbac_manager.check_permission("cached_user", "mcp:read")
        assert result2 is True
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_cache_invalidation(self, rbac_manager):
        """Test cache invalidation when roles change."""
        # Setup
        rbac_manager.define_role("cache_test", ["mcp:read"])
        rbac_manager.assign_role("cache_user", "cache_test")
        
        # Check permission to populate cache
        rbac_manager.check_permission("cache_user", "mcp:read")
        assert "cache_user" in rbac_manager.permission_cache
        
        # Revoke role should clear cache
        rbac_manager.revoke_role("cache_user", "cache_test")
        assert "cache_user" not in rbac_manager.permission_cache
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_get_user_permissions(self, populated_rbac_manager):
        """Test getting all permissions for a user."""
        permissions = populated_rbac_manager.get_user_permissions("regular_user")
        
        assert isinstance(permissions, list)
        assert len(permissions) > 0
        
        # Should contain expected permissions
        permission_strings = [p for p in permissions]
        assert any("mcp:read" in p for p in permission_strings)
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_list_roles(self, populated_rbac_manager):
        """Test listing all defined roles."""
        roles = populated_rbac_manager.list_roles()
        
        assert isinstance(roles, list)
        assert len(roles) >= 3  # guest, user, admin
        
        # Check role information structure
        for role_info in roles:
            assert "name" in role_info
            assert "description" in role_info
            assert "permissions" in role_info
            assert "is_active" in role_info
            assert "created_at" in role_info
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_role_deletion(self, rbac_manager):
        """Test role deletion functionality."""
        # Define role
        rbac_manager.define_role("temp_role", ["mcp:read"])
        assert "temp_role" in rbac_manager.roles
        
        # Delete role
        rbac_manager.delete_role("temp_role")
        assert "temp_role" not in rbac_manager.roles
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_role_deletion_with_assigned_users(self, rbac_manager):
        """Test that role deletion fails when users are assigned."""
        # Setup
        rbac_manager.define_role("assigned_role", ["mcp:read"])
        rbac_manager.assign_role("test_user", "assigned_role")
        
        # Should not be able to delete role with assigned users
        with pytest.raises(AuthorizationError, match="Cannot delete role.*still assigned"):
            rbac_manager.delete_role("assigned_role")
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_add_permission_to_role(self, rbac_manager):
        """Test adding permission to existing role."""
        # Define role
        rbac_manager.define_role("expandable_role", ["mcp:read"])
        
        # Add permission
        rbac_manager.add_permission_to_role("expandable_role", "mcp:write")
        
        # Assign user and test
        rbac_manager.assign_role("test_user", "expandable_role")
        
        assert rbac_manager.check_permission("test_user", "mcp:read")
        assert rbac_manager.check_permission("test_user", "mcp:write")
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_remove_permission_from_role(self, rbac_manager):
        """Test removing permission from role."""
        # Define role with multiple permissions
        rbac_manager.define_role("reducible_role", ["mcp:read", "mcp:write"])
        rbac_manager.assign_role("test_user", "reducible_role")
        
        # Verify both permissions exist
        assert rbac_manager.check_permission("test_user", "mcp:read")
        assert rbac_manager.check_permission("test_user", "mcp:write")
        
        # Remove one permission
        rbac_manager.remove_permission_from_role("reducible_role", "mcp:write")
        
        # Should still have read but not write
        assert rbac_manager.check_permission("test_user", "mcp:read")
        assert not rbac_manager.check_permission("test_user", "mcp:write")
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_authorization_context_creation(self, rbac_manager):
        """Test authorization context creation helper."""
        context = rbac_manager.create_authorization_context(
            user_id="test_user",
            ip_address="192.168.1.100",
            user_agent="Test-Agent/1.0"
        )
        
        assert isinstance(context, AuthorizationContext)
        assert context.user_id == "test_user"
        assert context.ip_address == "192.168.1.100"
        assert context.user_agent == "Test-Agent/1.0"
        assert isinstance(context.time_of_day, int)
        assert isinstance(context.day_of_week, int)
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_ip_range_conditions(self, rbac_manager):
        """Test IP range conditional permissions."""
        # Create permission with IP restrictions
        ip_restricted_permission = Permission(
            action="mcp:admin",
            conditions={"ip_range": ["192.168.1.*", "10.0.0.*"]}
        )
        
        role = Role(name="ip_restricted", permissions=[ip_restricted_permission])
        rbac_manager.roles["ip_restricted"] = role
        rbac_manager.assign_role("ip_user", "ip_restricted")
        
        # Test allowed IP
        allowed_context = AuthorizationContext(
            user_id="ip_user",
            ip_address="192.168.1.100"
        )
        
        result = rbac_manager.check_permission(
            "ip_user", "mcp:admin", context=allowed_context
        )
        assert result is True
        
        # Test disallowed IP
        disallowed_context = AuthorizationContext(
            user_id="ip_user",
            ip_address="203.0.113.1"
        )
        
        result = rbac_manager.check_permission(
            "ip_user", "mcp:admin", context=disallowed_context
        )
        assert result is False
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_day_of_week_conditions(self, rbac_manager):
        """Test day of week conditional permissions."""
        # Create permission restricted to weekdays (Monday=0 to Friday=4)
        weekday_permission = Permission(
            action="mcp:business",
            conditions={"day_of_week": [0, 1, 2, 3, 4]}
        )
        
        role = Role(name="weekday_only", permissions=[weekday_permission])
        rbac_manager.roles["weekday_only"] = role
        rbac_manager.assign_role("business_user", "weekday_only")
        
        # Test weekday (Wednesday = 2)
        weekday_context = AuthorizationContext(
            user_id="business_user",
            day_of_week=2
        )
        
        result = rbac_manager.check_permission(
            "business_user", "mcp:business", context=weekday_context
        )
        assert result is True
        
        # Test weekend (Saturday = 5)
        weekend_context = AuthorizationContext(
            user_id="business_user",
            day_of_week=5
        )
        
        result = rbac_manager.check_permission(
            "business_user", "mcp:business", context=weekend_context
        )
        assert result is False
